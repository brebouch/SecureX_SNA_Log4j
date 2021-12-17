#!/usr/bin/python3.8
# Cisco Secure Network Analytics log4j Responder
import sys
import dns.resolver
import requests
import argparse
import base64
import json
import re
from dns import resolver
import utilities
import sna
import orbital

logger = utilities.get_logger('app')


parser = argparse.ArgumentParser(description='SecureX Log4j Responder', add_help=False)
parser.add_argument('o', help='Lookup operation to be performed: full_lookup, url_lookup, orbital_lookup')
parser.add_argument('-u', help='Comma deliminated list of pages to scrape for observables, no spaces')
parser.add_argument('-s', help='Update Secure Network Analytics Host Group IPs with those found in url lookup',
                    action='store_true')
parser.add_argument('-q', help='SQL query for orbital to execute', required=False)
parser.add_argument('-n', help='Comma seperated list of nodes for Orbital to query, defaults to all, no spaces',
                    required=False)


lookup_urls = []
missed_urls = []
malicious_ips = []
deliberate_domains = []


def get_token(i, s):
    b64 = base64.b64encode((i + ':' + s).encode()).decode()
    url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'
    payload = 'grant_type=client_credentials'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': 'Basic ' + b64
    }
    res = requests.post(url, headers=headers, data=payload, verify=False)
    if res.status_code == 200:
        logger.info('SecureX Token Obtained')
        return res.json()['access_token']
    logger.debug(str(res) + ' - ' + res.text)
    logger.info('Issue Generating Token, Please Check Configuration and Try Again')


def ctr_inspect(lookup_string):
    url = 'https://visibility.amp.cisco.com/iroh/iroh-inspect/inspect'
    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    data = json.dumps({"content": lookup_string})
    res = requests.post(url, headers=headers, data=data)
    if res.status_code == 200:
        logger.info('Page inspection for observables complete')
        return res.json()
    logger.debug(str(res) + ' - ' + res.text)


def ctr_deliberate(domains):
    url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/deliberate/observables'
    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    data = json.dumps(domains)
    res = requests.post(url, headers=headers, data=data)
    if res.status_code == 200:
        logger.info('Domain deliberations complete')
        return res.json()
    logger.info('Domain deliberations lookup failed')
    logger.debug(str(res) + ' - ' + res.text)


def get_page_data(url):
    headers = {'User-Agent': 'SecureX/definition_workflow_01FX7FQDZRDUX1TWgKJwTPBMaOWrgUOld2q'}
    res = requests.get(url, verify=False, headers=headers)
    if res.status_code == 200:
        logger.info('Obtained page data for url:' + url)
        return res.text
    logger.info('Could not get page data for url: ' + url)
    logger.debug(str(res) + ' - ' + res.text)


def update_urls(url_string):
    split_urls = url_string.split(',')
    for s in split_urls:
        if s not in lookup_urls:
            lookup_urls.append(s)
            logger.info('Added to lookup url list:' + s)


def ip_lookup(domain):
    res = resolver.Resolver()
    res.nameservers = ['208.67.222.222', '208.67.220.220']
    try:
        resolved = res.query(domain)
        logger.debug('Resolved domains:' + str(resolved))
        logger.info('IP addresses obtained for: ' + domain)
        return resolved
    except dns.resolver.NXDOMAIN as e:
        logger.debug(e)
        return []


def update_malicious_ip(ip):
    if ip not in malicious_ips:
        malicious_ips.append(ip)
        logger.debug('Added to malicious ip list:' + ip)


def log_update(log_name, log_json):
    with open(log_name, 'w') as log:
        log.write(json.dumps(log_json, indent=4, sort_keys=True))
        logger.debug('Updated export file: ' + log_name)


def parse_observables(observables):
    lookup_domains = []
    logger.debug('Parsing observables, current observable type: ' + str(type(observables)))
    for o in observables:
        logger.debug('Parsing observable, current observable type: ' + str(o))
        if o['type'] == 'ip':
            update_malicious_ip(o['value'])
        elif o['type'] == 'domain':
            lookup_domains.append(o)
    if lookup_domains:
        logger.info('Obtaining SecureX verdicts for ' + str(len(lookup_domains)) + ' domains')
        lookup_identified_domains(lookup_domains)
    if malicious_ips:
        log_update('malicious_ips.json', {'malicious_ips': malicious_ips})


def lookup_identified_domains(domains):
    deliberations = ctr_deliberate(domains)
    logger.debug('Obtained deliberations: ' + json.dumps(deliberations))
    for d in deliberations['data']:
        try:
            if 'verdicts' not in d['data'].keys():
                continue
            if d['data']['verdicts']['count'] > 0:
                for v in d['data']['verdicts']['docs']:
                    if v['disposition'] == 2 or v['disposition'] == 3:
                        ips = ip_lookup(d['data']['verdicts']['observable']['value'])
                        for i in ips:
                            malicious_ips.append(i.address)
        except Exception as e:
            logger.debug('Exception thrown:' + str(e))


def strip_html(page):
    # Strip <script /> tags
    page = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', str(page), flags=re.DOTALL)
    # Strip <style /> tags
    page = re.sub(r'<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>', '', page, flags=re.DOTALL)
    # Strip other HTML
    page = re.sub(r'<[^<]+?>', '', page, flags=re.DOTALL)
    # Replace new lines with a space
    return page.replace("\n", " ")


def lookup_pages():
    for u in lookup_urls:
        if not u.startswith('http'):
            u = 'https://' + u
        page = get_page_data(u)
        if page is None:
            missed_urls.append(u)
            logger.info('Adding url to missed url: ' + u)
            continue
        parse_observables(ctr_inspect(strip_html(page)))


def url_ioc_lookup(pages):
    logger.info('Adding urls to list for lookups')
    update_urls(pages)
    logger.info('Performing page inspection for observables, be aware, this can take a few minutes.')
    lookup_pages()


if __name__ == '__main__':
    args = vars(parser.parse_args())
    if args['o'] == 'full_lookup' or args['o'] == 'url_lookup':
        if not utilities.verify_config('securex'):
            logger.critical('SecureX API credentials must be configured in order to proceed')
            sys.exit()
        securex = utilities.cfg['securex']
        token = get_token(securex['client_id'], securex['api_key'])
        url_ioc_lookup(args['u'])
        if utilities.verify_config('sna') and args['s']:
            sna_cfg = utilities.cfg['sna']
            logger.info('Obtained Secure Network Analytics credentials')
            sna = sna.NetworkAnalytics(sna_cfg['hostname'], sna_cfg['user'], sna_cfg['password'], logger)
            sna.set_host_group(sna_cfg['hostgroup'])
            sna.update_hostgroup(malicious_ips)
    if args['o'] == 'full_lookup' or args['o'] == 'orbital_lookup'and utilities.verify_config('orbital'):
        orb = utilities.cfg['orbital']
        o = orbital.Orbital(orb['client_id'], orb['api_key'], logger)
        if args['n']:
            for n in args['n'].split(','):
                o.add_node(n)
        else:
            o.add_node('all')
        if args['q']:
            o.add_os_query(args['q'])
        response = o.create_orbital_query()
        results = o.get_results(response['ID'])
        log_update('orbital_data.json', {'results' : results})
        logger.info('Results logged to orbital_data.json')
    logger.info('Actions complete, exiting application')




