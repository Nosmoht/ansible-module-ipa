#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import json


class IPAClient:
    def __init__(self, host, port, username, password, protocol):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.protocol = protocol

    def get_base_url(self):
        return '{prot}://{host}/ipa'.format(prot=self.protocol, host=self.host)

    def get_cookies(self, module):
        s = requests.session()
        url = '{base_url}/session/login_password'.format(base_url=self.get_base_url())
        data = dict(user=self.username, password=self.password)
        headers = {'referer': self.get_base_url(),
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'text/plain'}
        s = requests.post(url=url, data=data, headers=headers, verify=False)
        s.raise_for_status()
        return s.cookies

    def find_user(self, module, name, cookies):
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())
        headers = {'referer': self.get_base_url(),
                   'Content-Type': 'application/json',
                   'Accept': 'application/json'}
        data = {'method': 'user_find', 'params': [[str(name)], {}], 'id': 0}
        r = requests.post(url=url, data=json.dumps(data), headers=headers, cookies=cookies, verify=False)
        r.raise_for_status()
        response = json.loads(r.content)
        err = response.get('error')
        if err != None:
            module.fail_json(msg=err)

        return json.loads(r.text)


def ensure(module, client):
    cookies = client.get_cookies(module=module)
    user = client.find_user(module=module, name=module.params['name'], cookies=cookies)

    return False, user


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            password=dict(type='str', required=False),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            ipa_prot=dict(type='str', required=False, default='https', choices=['http', 'https']),
            ipa_host=dict(type='str', required=False, default='ipa.example.com'),
            ipa_port=dict(type='int', required=False, default=443),
            ipa_user=dict(type='str', required=False, default='admin'),
            ipa_pass=dict(type='str', required=True),
        ),
        supports_check_mode=True,
    )

    client = IPAClient(host=module.params['ipa_host'],
                       port=module.params['ipa_port'],
                       username=module.params['ipa_user'],
                       password=module.params['ipa_pass'],
                       protocol=module.params['ipa_prot'])

    changed, user = ensure(module, client)
    module.exit_json(changed=changed, user=user)


from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
