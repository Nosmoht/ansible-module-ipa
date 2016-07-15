#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import json


class IPAClient:
    def __init__(self, module, host, port, username, password, protocol):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.protocol = protocol
        self.headers = {'referer': self.get_base_url(),
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'}
        self.cookies = None
        self.module = module

    def get_base_url(self):
        return '{prot}://{host}/ipa'.format(prot=self.protocol, host=self.host)

    def login(self):
        s = requests.session()
        url = '{base_url}/session/login_password'.format(base_url=self.get_base_url())
        data = dict(user=self.username, password=self.password)
        headers = {'referer': self.get_base_url(),
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'text/plain'}
        try:
            s = requests.post(url=url, data=data, headers=headers, verify=False)
            s.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error on login: {}'.format(e.message))
        self.cookies = s.cookies

    def sudorule_find(self, name):
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())
        data = {'method': 'sudorule_find', 'params': [[name], {}]}

        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, cookies=self.cookies, verify=False)
            r.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error on post sudorule_find request: {}'.format(e.message))

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self.module.fail_json(msg='error in sudorule_find response: {}'.format(err))

        return resp.get('result').get('result')

    def sudorule_add(self, name, description=None, ipasudoopt=None):
        sudorule = {}
        if ipasudoopt is not None:
            sudorule['ipasudoopt'] = ipasudoopt
        if description is not None:
            sudorule['description'] = description

        data = {'method': 'sudorule_add', 'params': [[name], sudorule]}
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())

        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, verify=False, cookies=self.cookies)
            r.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error while posting sudorule_add request: {}'.format(e.message))

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self.module.fail_json(msg=err)

    def sudorule_del(self, uid):
        data = {'method': 'sudorule_del', 'params': [[uid], {}]}
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())

        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, verify=False, cookies=self.cookies)
            r.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error while posting sudorule_del request: {}'.format(e.message))

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self.module.fail_json(msg='error in sudorule_del response: {}'.format(err))


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']

    sudorule = client.sudorule_find(name=name)
    if not sudorule:
        if state == 'present':
            if module.check_mode:
                return True, None
            client.sudorule_add(name=name, description=module.params['description'],
                                ipasudoopt=module.params['sudoopt'])
            return True, client.sudorule_find(name)
    else:
        if state == 'absent':
            if module.check_mode:
                return True, sudorule
            client.sudorule_del(name)
            return True, None
    return False, sudorule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cn=dict(type='str', required=True, aliases=['name']),
            description=dict(type='str', required=False),
            sudoopt=dict(type='str', required=False),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            ipa_prot=dict(type='str', required=False, default='https', choices=['http', 'https']),
            ipa_host=dict(type='str', required=False, default='ipa.example.com'),
            ipa_port=dict(type='int', required=False, default=443),
            ipa_user=dict(type='str', required=False, default='admin'),
            ipa_pass=dict(type='str', required=True, no_log=True),
        ),
        supports_check_mode=True,
    )

    client = IPAClient(module=module,
                       host=module.params['ipa_host'],
                       port=module.params['ipa_port'],
                       username=module.params['ipa_user'],
                       password=module.params['ipa_pass'],
                       protocol=module.params['ipa_prot'])
    try:
        client.login()
        changed, sudorule = ensure(module, client)
        module.exit_json(changed=changed, sudorule=sudorule)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
