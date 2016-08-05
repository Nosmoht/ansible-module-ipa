#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_group
short_description: Manager IPA group
description:
- Add, modify and delete group within IPA server
options:
  name:
    description:
    - Group name
    required: true
  gidnumber:
    description:
    - GID
    required: false
  state:
    description: State to ensure
    required: false
    default: "present"
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

EXAMPLES = '''
# Ensure group is present
- ipa_group:
    name: oinstall
    gidnumber: 54321
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

# Ensure brain is absent
- ipa_group:
    name: oinstall
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
'''

RETURN = '''
user:
  description: JSON data of group as returned by IPA
  returned: if found
  type: string
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

    def group_find(self, name):
        return self._post_json(method='group_find', name=name)

    def group_add(self, name, description=None, external=None, gid=None, nonposix=None):
        group = {}
        if description is not None:
            group['description'] = description
        if external is not None:
            group['external'] = external
        if gid is not None:
            group['gidnumber'] = gid
        if nonposix is not None:
            group['nonposix'] = nonposix

        return self._post_json(method='group_add', name=name, item=group)

    def group_del(self, name):
        return self._post_json(method='group_del', name=name)


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']

    group = client.group_find(name=name)
    if not group:
        if state == 'present':
            client.group_add(name, description=module.params['description'], external=module.params['external'],
                             gid=module.params['gidnumber'], nonposix=module.params['nonposix'])
            return True, client.group_find(name)
    else:
        if state == 'absent':
            client.group_del(name)
            return True, None
    return False, group


def main():
    module = AnsibleModule(
        argument_spec=dict(
            description=dict(type='str', required=False),
            external=dict(type='bool', required=False),
            gidnumber=dict(type='str', required=False, aliases=['gid']),
            cn=dict(type='str', required=True, aliases=['name']),
            nonposix=dict(type='str', required=False),
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
        changed, group = ensure(module, client)
        module.exit_json(changed=changed, group=group)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
