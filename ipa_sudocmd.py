#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_sudocmd
author: Thomas Krahn (@Nosmoht)
short_description: Manager IPA sudo command
description:
- Add, modify or delete sudo command within IPA server using IPA API.
options:
  sudocmd:
    description:
    - Sudo Command.
    aliases: ['name']
    required: true
  description:
    description:
    - Group description.
  state:
    description: State to ensure
    required: false
    default: present
    choices: ['present', 'absent']
  ipa_port:
    description: Port of IPA server
    required: false
    default: 443
  ipa_host:
    description: IP or hostname of IPA server
    required: false
    default: "ipa.example.com"
  ipa_user:
    description: Administrative account used on IPA server
    required: false
    default: "admin"
  ipa_pass:
    description: Password of administrative user
    required: true
  ipa_prot:
    description: Protocol used by IPA server
    required: false
    default: "https"
    choices: ["http", "https"]
'''

import json

import requests


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

    def get_json_url(self):
        return '{base_url}/session/json'.format(base_url=self.get_base_url())

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
            self._fail('login', e)
        self.cookies = s.cookies

    def _fail(self, msg, e):
        if 'message' in e:
            err_string = e.get('message')
        else:
            err_string = e
        self.module.fail_json(msg='{}: {}'.format(msg, err_string))

    def _post_json(self, method, name, item=None):
        if item is None:
            item = {}

        url = '{base_url}/session/json'.format(base_url=self.get_base_url())
        data = {'method': method, 'params': [[name], item]}
        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, cookies=self.cookies, verify=False)
            r.raise_for_status()
        except Exception as e:
            self._fail('post {}'.format(method), e)

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self._fail('repsonse {}'.format(method), err)

        if 'result' in resp:
            result = resp.get('result')
            if 'result' in result:
                result = result.get('result')
                if isinstance(result, list):
                    if len(result) > 0:
                        return result[0]
            return result
        return None

    def sudocmd_find(self, name):
        return self._post_json(method='sudocmd_find', name=None, item={'all': True, 'sudocmd': name})

    def sudocmd_add(self, name, item):
        return self._post_json(method='sudocmd_add', name=name, item=item)

    def sudocmd_mod(self, name, item):
        return self._post_json(method='sudocmd_mod', name=name, item=item)

    def sudocmd_del(self, name):
        return self._post_json(method='sudocmd_del', name=name)


def get_sudocmd_dict(description=None):
    data = {}
    if description is not None:
        data['description'] = description
    return data


def get_sudocmd_diff(ipa_sudocmd, module_sudocmd):
    data = []
    for key in module_sudocmd.keys():
        module_value = module_sudocmd.get(key, None)
        ipa_value = ipa_sudocmd.get(key, None)
        if isinstance(ipa_value, list) and not isinstance(module_value, list):
            module_value = [module_value]
        if isinstance(ipa_value, list) and isinstance(module_value, list):
            ipa_value = sorted(ipa_value)
            module_value = sorted(module_value)
        if ipa_value != module_value:
            data.append(key)
    return data


def ensure(module, client):
    name = module.params['sudocmd']
    state = module.params['state']

    module_sudocmd = get_sudocmd_dict(description=module.params['description'])
    ipa_sudocmd = client.sudocmd_find(name=name)

    changed = False
    if state == 'present':
        if not ipa_sudocmd:
            changed = True
            if not module.check_mode:
                client.sudocmd_add(name=name, item=module_sudocmd)
        else:
            diff = get_sudocmd_diff(ipa_sudocmd, module_sudocmd)
            if len(diff) > 0:
                changed = True
                if not module.check_mode:
                    client.sudocmd_mod(name=name, item={key: module_sudocmd.get(key) for key in diff})
    else:
        if ipa_sudocmd:
            changed = True
            if not module.check_mode:
                client.sudocmd_del(name=name)

    return changed, client.sudocmd_find(name=name)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            description=dict(type='str', required=False),
            state=dict(type='str', required=False, default='present',
                       choices=['present', 'absent', 'enabled', 'disabled']),
            sudocmd=dict(type='str', required=True, aliases=['name']),
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
        changed, sudocmd = ensure(module, client)
        module.exit_json(changed=changed, sudorule=sudocmd)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
