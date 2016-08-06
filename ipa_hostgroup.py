#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_hostgroup
short_description: Manager IPA hostgroup
description:
- Add, modify and delete an IPA hostgroup using IPA API
options:
  cn:
    description:
    - Canonical name.
    - Can not be changed as it is the unique identifier.
    required: true
    aliases: ["name"]
  description:
    description: Description
    required: false
  host:
    description:
    - List of hosts that belong to the hostgroup.
    - If an empty list is passed all hosts will be removed from the group.
    required: false
  state:
    description: State to ensure
    required: false
    default: "present"
    choices: ["present", "absent"]
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
requirements:
- Python requests
'''

EXAMPLES = '''
# Ensure hostgroup databases is present
- ipa_hostgroup:
    name: databases
    state: present
    host:
    - db.example.com
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

# Ensure hostgroup databases is absent
- ipa_hostgroup:
    name: databases
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
'''

RETURN = '''
hostgroup:
  description: JSON data of hostgroup as returned by IPA
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

    def hostgroup_find(self, name):
        return self._post_json(method='hostgroup_find', name=name)

    def hostgroup_add(self, name, hostgroup):
        return self._post_json(method='hostgroup_add', name=name, item=hostgroup)

    def hostgroup_mod(self, name, hostgroup):
        return self._post_json(method='hostgroup_mod', name=name, item=hostgroup)

    def hostgroup_del(self, name):
        return self._post_json(method='hostgroup_del', name=name)

    def hostgroup_add_member(self, name, host):
        return self._post_json(method='hostgroup_add_member', name=name, item=host)

    def hostgroup_remove_member(self, name, host):
        return self._post_json(method='hostgroup_remove_member', name=name, item=host)


def get_hostgroup_dict(description=None):
    data = {}
    if description is not None:
        data['description'] = description
    return data


def ensure(module, client):
    name = module.params['name']
    state = module.params['state']
    host = module.params['host']
    if host is not None:
        host.sort()

    ipa_hostgroup = client.hostgroup_find(name=name)
    hostgroup = get_hostgroup_dict(description=module.params['description'])

    if state == 'present':
        if not ipa_hostgroup:
            if not module.check_mode:
                client.hostgroup_add(name=name, hostgroup=hostgroup)

            if host is not None:
                if not module.check_mode:
                    client.hostgroup_add_member(name=name, host={'host': host})

            return True, client.hostgroup_find(name=name)

        changed = False
        # Host members
        if host is not None:
            ipa_host = ipa_hostgroup.get('member_host', [])

            # Hosts that a part of the group but shouldn't must be removed
            hosts = list(set(ipa_host) - set(host))
            if len(hosts) > 0:
                if not module.check_mode:
                    client.hostgroup_remove_member(name=name, host={'host': hosts})
                changed = True

            # Hosts that a not port of the group but should must be added
            hosts = list(set(host) - set(ipa_host))
            if len(hosts) > 0:
                if not module.check_mode:
                    client.hostgroup_add_member(name=name, host={'host': hosts})
                changed = True

        if changed:
            return True, client.hostgroup_find(name=name)
        return False, ipa_hostgroup
    else:
        if ipa_hostgroup:
            if not module.check_mode:
                client.hostgroup_del(name=name)
            return True, None
    return False, ipa_hostgroup


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cn=dict(type='str', required=True, aliases=['name']),
            description=dict(type='str', required=False),
            host=dict(type='list', required=False),
            state=dict(type='str', required=False, default='present',
                       choices=['present', 'absent', 'enabled', 'disabled']),
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
        changed, hostgroup = ensure(module, client)
        module.exit_json(changed=changed, hostgroup=hostgroup)
    except Exception as e:
        module.fail_json(msg=e.message)


if __name__ == '__main__':
    main()
