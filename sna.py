import requests
import json
import sys


try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


class NetworkAnalytics:

    host_group = ''
    host_group_name = ''
    tenant = ""
    XSRF_HEADER_NAME = 'X-XSRF-TOKEN'
    session = ''

    def get_session(self):
        data = {'username': self.username, 'password': self.password}
        api_session = requests.Session()
        res = api_session.post(self.url + '/token/v2/authenticate', data=data, verify=False)
        if res.status_code == 200:
            for cookie in res.cookies:
                if cookie.name == 'XSRF-TOKEN':
                    api_session.headers.update({self.XSRF_HEADER_NAME: cookie.value})
            api_session.cookies = res.cookies
            self.logger.info('Secure Network Analytics Session Opened Successfully')
            self.session = api_session
            return
        self.logger.info('Issue obtaining session token, check credentials and try again')
        self.logger.debug(str(res) + ' - ' + res.text)
        sys.exit()

    def get_tenant(self):
        res = self.session.get(self.url + '/sw-reporting/v1/tenants/', verify=False)
        if res.status_code == 200:
            data = json.loads(res.content)
            self.logger.info('Obtained Tenant ID')
            self.tenant = str(data['data'][0]['id'])
            return
        self.logger.info('Issue obtaining tenant ID, check credentials and try again')
        self.logger.debug(str(res) + ' - ' + res.text)
        sys.exit()

    def get_hostgroup(self, hg_id):
        hg_url = self.url + '/smc-configuration/rest/v1/tenants/' + self.tenant + '/tags/' + hg_id
        res = self.session.get(hg_url, verify=False)
        if res.status_code == 200:
            self.logger.info('Obtained Host Group Data')
            return json.loads(res.content)['data']
        self.logger.info('Issue obtaining host group, check configuration and try again')
        self.logger.debug(str(res) + ' - ' + res.text)
        sys.exit()

    def get_hostgroup_by_name(self):
        hg_url = self.url + '/smc-configuration/rest/v1/tenants/' + self.tenant + '/tags/'
        res = self.session.get(hg_url, verify=False)
        if res.status_code == 200:
            data = json.loads(res.content)
            for d in data['data']:
                if d['name'] == self.host_group_name:
                    self.host_group = self.get_hostgroup(str(d['id']))
                    self.logger.info('Found Host Group: ' + self.host_group_name + ' ID: ' + str(d['id']))
                    return
        self.logger.info('Issue obtaining host group, check configuration and try again')
        self.logger.debug(str(res) + ' - ' + res.text)
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
            self.logger.info('Host Group Successfully Updated')
        else:
            self.logger.info('Issue Updating Host Group')
            self.logger.debug(str(res) + ' - ' + res.text)

    def set_host_group(self, hg):
        self.host_group_name = hg
        self.get_hostgroup_by_name()

    def __init__(self, ip, user, passwd, logger):
        self.host = ip
        self.url = 'https://' + ip
        self.username = user
        self.password = passwd
        self.logger = logger
        self.get_session()
        self.get_tenant()


if __name__ == '__main__':
    sna = NetworkAnalytics(sys.argv[1], sys.argv[2], sys.argv[3])
    sna.set_host_group(sys.argv[4])
    sna.update_hostgroup(sys.argv[5].split(','))

