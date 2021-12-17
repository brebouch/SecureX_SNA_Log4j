import json
import requests
import base64
import time


class Orbital:
    url = 'https://orbital.amp.cisco.com'
    nodes = []
    os = []
    os_query = []
    token = None
    logger = None

    queries = [
        'SELECT name, value FROM ( SELECT name, value FROM orbital_environment UNION SELECT name AS "name", data AS "value" FROM registry WHERE key LIKE "HKEY_USERS\%\Environment") AS t WHERE value like "%java%"; ',
        'SELECT p2.name AS parent_process, p1.pid, p1.name, p1.path, p1.cmdline, p1.state, p1.uid FROM processes p1 JOIN processes p2 ON p1.pid=p2.parent WHERE p1.name like "%java%"; ',
        'SELECT path, matches, count, strings FROM yara WHERE path IN ( SELECT path FROM file WHERE (directory LIKE "C:\Program Files\%" AND filename LIKE "%.jar") OR (directory LIKE "C:\Program Files (x86)\%" AND filename LIKE "%.jar") ) AND sigrule=\'rule suspicious_log4j_string { strings: $s1="JndiLookup.class" wide ascii nocase condition: $s1}\'; ',
        'SELECT name, version, install_location, install_source, install_date FROM programs WHERE (name LIKE "%log4j%" OR name LIKE "%java%"); ',
        'SELECT pid, name, path, cmdline FROM processes WHERE name LIKE "%log4j%" AND parent LIKE "%java%";',
        'SELECT pid, path FROM process_open_files WHERE path LIKE \'%log4j%.jar\';',
        "SELECT name, version, source FROM deb_packages WHERE name LIKE '%log4j%';",
        "SELECT name, version, source FROM npm_packages WHERE name LIKE '%log4j%';",
        "SELECT name, version, source FROM rpm_packages WHERE name LIKE '%log4j%';",
        "SELECT name, version, source FROM apt_sources WHERE name LIKE '%log4j%';",
        "SELECT name, version, install_location FROM programs WHERE name LIKE '%log4j%';",
        'SELECT filename, directory FROM file WHERE path LIKE "/usr/local/apache-log4j%";'
    ]

    def get_token(self):
        b64 = base64.b64encode((self.api_client + ':' + self.api_password).encode()).decode()
        url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'
        payload = 'grant_type=client_credentials'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'Authorization': 'Basic ' + b64
        }
        res = requests.post(url, headers=headers, data=payload)
        if res.status_code == 200:
            self.logger.info('SecureX Token Obtained')
            self.token = res.json()['access_token']
            return
        self.logger.debug(str(res) + ' - ' + res.text)
        print('Issue Generating Token, Please Check Configuration and Try Again  \n')

    def add_node(self, node):
        self.nodes.append(node)
        self.logger.debug('Added node: ' + node)

    def add_os(self, os):
        self.os.append(os)
        self.logger.debug('Added os: ' + os)

    def add_os_query(self, query):
        self.os_query.append({
            'sql': query})
        self.logger.debug('Added query: ' + query)

    def create_orbital_query(self):
        timer_expiry = int(time.time()) + 60
        headers = {
            'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        data = {
            "osQuery": self.os_query,
            "nodes": self.nodes,
            "expiry": timer_expiry,
        }
        full_url = self.url + '/v0/query'
        res = requests.post(full_url, headers=headers, data=json.dumps(data))
        if res.status_code == 200:
            self.logger.info('Query created successfully, waiting for results')
            time.sleep(len(self.os_query))
            return res.json()
        self.logger.info('Issue Creating Query, Please Check Configuration and Try Again')
        self.logger.debug(str(res) + ' - ' + res.text)

    def pull_results(self, result_id):
        headers = {
            'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        full_url = self.url + '/v0/jobs/' + result_id + '/results'
        return requests.get(full_url, headers=headers)

    def get_results(self, result_id):
        while True:
            results = self.pull_results(result_id)
            if results.status_code != 404:
                if results.status_code == 200:
                    self.logger.info('Results received, sending to be parsed')
                    parsed = self.parse_results(results.json())
                    if parsed:
                        self.logger.info('Results parsed, returning parsed results')
                        return parsed
            self.logger.debug('Unable to parse results, waiting a second and tying again')
            self.logger.debug(str(results) + ' - ' + results.text)
            time.sleep(1)

    def slice_per(self, source, step):
        return [source[i::step] for i in range(step)]

    def parse_results(self, results):
        response = []
        self.logger.info('Parsing results')
        if not results:
            self.logger.debug('Results NONE type, skipping and moving on')
            return
        self.logger.info('Obtained results count: ' + str(len(results['results'])))
        for res in range(len(results['results'])):
            r = results['results'][res]
            response.append({'hostinfo': r['hostinfo'], 'hits': []})
            for o in r['osQueryResult']:
                if o['values']:
                    self.logger.debug('Query values found, extracting result values')
                    split_values = self.slice_per(o['values'], len(o['columns']))
                    index = r['osQueryResult'].index(o)
                    update = r['osQuery'][index]
                    update.update({'matches': []})
                    for i in range(int(len(o['values']) / len(o['columns']))):
                        match = {}
                        for c in range(len(o['columns'])):
                            match.update({o['columns'][c]: split_values[c][i]})
                        self.logger.debug('Updating matches: ' + json.dumps(match))
                        update['matches'].append(match)
                    self.logger.debug('Updating response: ' + json.dumps(response))
                    response[res]['hits'].append(update)
        return response

    def __init__(self, client, password, logger):
        self.api_client = client
        self.api_password = password
        self.logger = logger
        self.get_token()
        for q in self.queries:
            self.add_os_query(q)
        self.logger.info('Orbital Client Created')


if __name__ == '__main__':
    print('hi')

