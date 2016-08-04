#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_role
short_description: Manager IPA role
description:
- Add, modify and delete a role within IPA server using IPA API
options:
  cn:
    description: Canonical name
    required: true
    aliases: ['name']
  description:
    description: Role description
    required: false
  state:
    description: State to ensure
    required: false
    default: "present"
    choices: ["present", "absent"]
  user:
    description: List of user names that belong to the role
    required: false
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
- name: ensure role is present
  ipa_role:
    name: dba
    description: Database Administrators
    state: present
    user:
    - pinky
    - brain
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret


- name: ensure role is absent
  ipa_role:
    name: dba
    state: absent
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
'''

RETURN = '''
role:
  description: JSON data of role as returned by IPA
  returned: if found
  type: string
'''

import json
import requests

from ansible.module_utils.basic import AnsibleModule


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

    def _post_json(self, method, name, item={}):
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

    def role_find(self, name):
        return self._post_json(method='role_find', name=name)

    def role_add(self, name, role):
        return self._post_json(method='role_add', name=name, item=role)

    def role_mod(self, name, role):
        return self._post_json(method='role_mod', name=name, item=role)

    def role_del(self, name):
        return self._post_json(method='role_del', name=name)

    def role_add_member(self, name, member):
        return self._post_json(method='role_add_member', name=name, item=member)

    def role_remove_member(self, name, member):
        return self._post_json(method='role_remove_member', name=name, item=member)


def get_role_dict(description=None):
    data = {}
    if description is not None:
        data['description'] = description
    return data


def role_diff(target, actual):
    data = []
    for key in target:
        target_value = target.get(key)
        actual_value = actual.get(key)
        if isinstance(actual_value, list) and not isinstance(target_value, list):
            target_value = [target_value]
        if target_value != actual_value:
            data.append(key)
    return data


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']
    user = module.params['user']
    if user is not None:
        user.sort()

    module_role = get_role_dict(description=module.params['description'])

    ipa_role = client.role_find(name=name)

    if not ipa_role:
        if state == 'present':
            if module.check_mode:
                module.exit_json(changed=True, role=module_role)

            client.role_add(name=name, role=module_role)

            if user is not None:
                client.role_add_member(name=name, member={'user': user})

            return True, client.role_find(name=name)
    else:
        if state == 'present':
            diff = role_diff(actual=ipa_role, target=module_role)
            if len(diff) > 0:

                if module.check_mode:
                    module.exit_json(changed=True, role=module_role)

                client.role_mod(name=name, role=module_role)
                return True, client.user_find(name=name)
        if state == 'absent':
            if module.check_mode:
                module.exit_json(changed=True, role=ipa_role)

            client.role_del(name)
            return True, None
    return False, ipa_role


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cn=dict(type='str', required=True, aliases=['name']),
            description=dict(type='str', required=False),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            user=dict(type='list', required=False),
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
        changed, role = ensure(module, client)
        module.exit_json(changed=changed, role=role)
    except Exception as e:
        module.fail_json(msg=e.message)


if __name__ == '__main__':
    main()
