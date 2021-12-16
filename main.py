# Cisco Secure Network Analytics log4j Responder
import dns.resolver
import requests
import argparse
import base64
import json
import re
from dns import resolver
import sna


parser = argparse.ArgumentParser(description='SecureX Relay Deployment Tool.', prog='SecureX Relay Deployer')
parser.add_argument('o', help='Comma deliminated list of pages to scrape for observables, no spaces')
parser.add_argument('-c', help='SecureX API Client ID. Example: "-i client_......"')
parser.add_argument('-s', help='SecureX API Client Secret')
parser.add_argument('-i', help='Secure Network Analytics IP address', required=False)
parser.add_argument('-u', help='Secure Network Analytics username', required=False)
parser.add_argument('-p', help='Secure Network Analytics password', required=False)
parser.add_argument('-g', help='Secure Network Analytics destination Host Group', required=False)


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
        return res.json()['access_token']
    print('Issue Generating Token, Please Check Configuration and Try Again  \n')


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
        return res.json()


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
        return res.json()


def get_page_data(url):
    headers = {'User-Agent': 'SecureX/definition_workflow_01FX7FQDZRDUX1TWgKJwTPBMaOWrgUOld2q'}
    res = requests.get(url, verify=False, headers=headers)
    if res.status_code == 200:
        return res.text


def update_urls(url_string):
    split_urls = url_string.split(',')
    for s in split_urls:
        if s not in lookup_urls:
            lookup_urls.append(s)


def get_lookup_pages(pages):
    for p in pages.split(','):
        lookup_urls.append(p)


def ip_lookup(domain):
    res = resolver.Resolver()
    res.nameservers = ['208.67.222.222', '208.67.220.220']
    try:
        return res.query(domain)
    except dns.resolver.NXDOMAIN:
        return []


def update_malicious_ip(ip):
    if ip not in malicious_ips:
        malicious_ips.append(ip)


def log_update():
    with open('malicious_ips.txt', 'w') as logger:
        logger.write(json.dumps({'malicious_ips': malicious_ips}, indent=4, sort_keys=True))


def parse_observables(observables):
    lookup_domains = []
    for o in observables:
        if o['type'] == 'ip':
            update_malicious_ip(o['value'])
        elif o['type'] == 'domain':
            lookup_domains.append(o)
    if lookup_domains:
        lookup_identified_domains(lookup_domains)
    if malicious_ips:
        log_update()


def lookup_identified_domains(domains):
    deliberations = ctr_deliberate(domains)
    for d in deliberations['data']:
        if d['data']['verdicts']['count'] > 0:
            for v in d['data']['verdicts']['docs']:
                if v['disposition'] == 2 or v['disposition'] == 3:
                    ips = ip_lookup(d['data']['verdicts']['observable']['value'])
                    for i in ips:
                        malicious_ips.append(i.address)


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
        try:
            page = get_page_data(u)
            if page is None:
                missed_urls.append(u)
                continue
            parse_observables(ctr_inspect(strip_html(page)))
        except:
            missed_urls.append(u)


if __name__ == '__main__':
    args = vars(parser.parse_args())
    token = get_token(args['c'], args['s'])
    get_lookup_pages(args['o'])
    lookup_pages()
    if 'i' in args.keys() and 'u' in args.keys() and 'p' in args.keys() and 'g' in args.keys():
        sna = sna.NetworkAnalytics(args['i'], args['u'], args['p'])
        sna.set_host_group(args['g'])
        sna.update_hostgroup(malicious_ips)




