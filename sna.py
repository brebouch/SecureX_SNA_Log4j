import requests
import json
import sys

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


class NetworkAnalytics:

    username = ""
    password = ""
    host = ""
    host_group = ''
    host_group_name = ''
    tenant = ""
    XSRF_HEADER_NAME = 'X-XSRF-TOKEN'
    session = ''

    url = ''

    def get_session(self):
        data = {'username': self.username, 'password': self.password}
        api_session = requests.Session()
        res = api_session.post(self.url + '/token/v2/authenticate', data=data, verify=False)
        if res.status_code == 200:
            for cookie in res.cookies:
                if cookie.name == 'XSRF-TOKEN':
                    api_session.headers.update({self.XSRF_HEADER_NAME: cookie.value})
            api_session.cookies = res.cookies
            print('Secure Network Analytics Session Opened Successfully')
            self.session = api_session
            return
        print('Issue obtaining session token, check credentials and try again')
        sys.exit()

    def get_tenant(self):
        res = self.session.get(self.url + '/sw-reporting/v1/tenants/', verify=False)
        if res.status_code == 200:
            data = json.loads(res.content)
            print('Obtained Tenant ID')
            self.tenant = str(data['data'][0]['id'])
            return
        print('Issue obtaining tenant ID, check credentials and try again')
        sys.exit()

    def get_hostgroup(self, hg_id):
        hg_url = self.url + '/smc-configuration/rest/v1/tenants/' + self.tenant + '/tags/' + hg_id
        res = self.session.get(hg_url, verify=False)
        if res.status_code == 200:
            print('Obtained Host Group Data')
            return json.loads(res.content)['data']
        print('Issue obtaining host group, check configuration and try again')
        sys.exit()

    def get_hostgroup_by_name(self):
        hg_url = self.url + '/smc-configuration/rest/v1/tenants/' + self.tenant + '/tags/'
        res = self.session.get(hg_url, verify=False)
        if res.status_code == 200:
            data = json.loads(res.content)
            for d in data['data']:
                if d['name'] == self.host_group_name:
                    self.host_group = self.get_hostgroup(str(d['id']))
                    return
        print('Issue obtaining host group, check configuration and try again')
        sys.exit()

    def update_hostgroup(self, ips):
        if not self.host_group:
            print('Host Group not defined, must be defined before updating')
            return
        hg_url = self.url + '/smc-configuration/rest/v1/tenants/' + self.tenant + '/tags/' + str(self.host_group['id'])
        for i in ips:
            if i not in self.host_group['ranges']:
                self.host_group['ranges'].append(i)
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        data = json.dumps(self.host_group)
        res = self.session.put(hg_url, data=data, headers=headers, verify=False)
        if res.status_code == 200:
            print('Host Group Successfully Updated')

    def set_host_group(self, hg):
        self.host_group_name = hg
        self.get_hostgroup_by_name()

    def __init__(self, ip, user, passwd):
        self.host = ip
        self.url = 'https://' + ip
        self.username = user
        self.password = passwd
        self.get_session()
        self.get_tenant()


if __name__ == '__main__':
    sna = NetworkAnalytics(sys.argv[1], sys.argv[2], sys.argv[3])
    sna.set_host_group(sys.argv[4])
    sna.update_hostgroup(sys.argv[5].split(','))

