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

    def _post_json(self, method, name, item={}):
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())
        data = {'method': method, 'params': [[name], item]}
        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, cookies=self.cookies, verify=False)
            r.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error on post {method} request: {err}'.format(method=method, err=e.message))

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self.module.fail_json(msg='error in {method} response: {err}'.format(method=method, err=err))

        if 'result' in resp:
            return resp.get('result').get('result')
        return None

    def sudorule_find(self, name):
        return self._post_json(method='sudorule_find', name=name)

    def sudorule_add(self, name, description=None, ipasudoopt=None):
        sudorule = {}
        if ipasudoopt is not None:
            sudorule['ipasudoopt'] = ipasudoopt
        if description is not None:
            sudorule['description'] = description
        return self._post_json(method='sudorule_add', name=name, item=sudorule)

    def sudorule_add_user(self, name, groups=None, users=None):
        data = {}
        if groups is not None:
            data['group'] = groups
        if users is not None:
            data['user'] = users
        return self._post_json(method='sudorule_add_user', name=name, item=data)

    def sudorule_del(self, uid):
        return self._post_json(method='sudorule_del', name=uid)


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

            groups = module.params['groups']
            if groups is not None:
                client.sudorule_add_user(name=name, groups=groups)

            users = module.params['users']
            if users is not None:
                client.sudorule_add_user(name=name, users=users)

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
            groups=dict(type='list', required=False),
            sudoopt=dict(type='str', required=False),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            users=dict(type='str', required=False),
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
