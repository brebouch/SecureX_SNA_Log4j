import json
import requests
import base64
import time


class Orbital:
    url = 'https://orbital.amp.cisco.com'
    api_client = ''
    api_password = ''
    nodes = []
    os = []
    os_query = []
    token = None

    queries = [
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
            self.token = res.json()['access_token']
            return
        print('Issue Generating Token, Please Check Configuration and Try Again')

    def add_node(self, node):
        self.nodes.append(node)

    def add_os(self, os):
        self.os.append(os)

    def add_os_query(self, query):
        self.os_query.append({
            'sql': query})

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
            time.sleep(len(self.os_query))
            return res.json()

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
                    parsed = self.parse_results(results.json())
                    if parsed:
                        return parsed
            time.sleep(1)

    def slice_per(self, source, step):
        return [source[i::step] for i in range(step)]

    def parse_results(self, results):
        response = []
        if not results:
            return
        for res in range(len(results['results'])):
            r = results['results'][res]
            response.append({'hostinfo': r['hostinfo'], 'hits': []})
            for o in r['osQueryResult']:
                if o['values']:
                    split_values = self.slice_per(o['values'], len(o['columns']))
                    index = r['osQueryResult'].index(o)
                    update = r['osQuery'][index]
                    update.update({'matches': []})
                    for i in range(int(len(o['values']) / len(o['columns']))):
                        match = {}
                        for c in range(len(o['columns'])):
                            match.update({o['columns'][c]: split_values[c][i]})
                        update['matches'].append(match)
                    response[res]['hits'].append(update)
        return response

    def __init__(self, client, password):
        self.api_client = client
        self.api_password = password
        self.get_token()
        for q in self.queries:
            self.add_os_query(q)


if __name__ == '__main__':
    print('hi')

