#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_sudorule
author: Thomas Krahn (@Nosmoht)
short_description: Manage FreeIPA sudo rule
description:
- Add, modify or delete sudo rule within IPA server using IPA API.
options:
  cn:
    description:
    - Canonical name.
    - Can not be changed as it is the unique identifier.
    required: true
    aliases: ['name']
  cmdcategory:
    description:
    - Command category the rule applies to.
    choices: ['all']
    required: false
  cmd:
    description:
    - List of commands assigned to the rule.
    - If an empty list is passed all commands will be removed from the rule.
    - If option is omitted commands will not be checked or changed.
    required: false
  host:
    description:
    - List of hosts assigned to the rule.
    - If an empty list is passed all hosts will be removed from the rule.
    - If option is omitted hosts will not be checked or changed.
    - Option C(hostcategory) must be omitted to assign hosts.
    required: false
  hostcategory:
    description:
    - Host category the rule applies to.
    - If 'all' is passed one must omit C(host) and C(hostgroup).
    - Option C(host) and C(hostgroup) must be omitted to assign 'all'.
    choices: ['all']
    required: false
  hostgroup:
    description:
    - List of host groups assigned to the rule.
    - If an empty list is passed all host groups will be removed from the rule.
    - If option is omitted host groups will not be checked or changed.
    - Option C(hostcategory) must be omitted to assign host groups.
    required: false
  user:
    description:
    - List of users assigned to the rule.
    - If an empty list is passed all users will be removed from the rule.
    - If option is omitted users will not be checked or changed.
    required: false
  usercategory:
    description:
    - User category the rule applies to.
    choices: ['all']
    required: false
  usergroup:
    description:
    - List of user groups assigned to the rule.
    - If an empty list is passed all user groups will be removed from the rule.
    - If option is omitted user groups will not be checked or changed.
    required: false
  state:
    description: State to ensure
    required: false
    default: present
    choices: ['present', 'absent', 'enabled', 'disabled']
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
version_added: "2.2"
requirements:
- json
- requests
'''

EXAMPLES = '''
# Ensure sudo rule is present thats allows all every body to execute any command on any host without beeing asked for a password.
- ipa_sudorule:
    name: sudo_all_nopasswd
    cmdcategory: all
    description: Allow to run every command with sudo without password
    hostcategory: all
    sudoopt:
    - '!authenticate'
    usercategory: all
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

# Ensure user group developers can run every command on host group db-server as well as on host db01.example.com.
```yaml
- ipa_sudorule:
    name: sudo_dev_dbserver
    description: Allow developers to run every command with sudo on all database server
    cmdcategory: all
    host:
    - db01.example.com
    hostgroup:
    - db-server
    sudoopt:
    - '!authenticate'
    usergroup:
    - developers
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```
'''

RETURN = '''
sudorule:
  description: Sudorule as returned by IPA
  returned: always
  type: dict
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

    def sudorule_find(self, name):
        return self._post_json(method='sudorule_find', name=None, item={'all': True, 'cn': name})

    def sudorule_add(self, name, item):
        return self._post_json(method='sudorule_add', name=name, item=item)

    def sudorule_mod(self, name, item):
        return self._post_json(method='sudorule_mod', name=name, item=item)

    def sudorule_del(self, name):
        return self._post_json(method='sudorule_del', name=name)

    def sudorule_add_option(self, name, item):
        return self._post_json(method='sudorule_add_option', name=name, item=item)

    def sudorule_add_option_ipasudoopt(self, name, item):
        return self.sudorule_add_option(name=name, item={'ipasudoopt': item})

    def sudorule_remove_option(self, name, item):
        return self._post_json(method='sudorule_remove_option', name=name, item=item)

    def sudorule_remove_option_ipasudoopt(self, name, item):
        return self.sudorule_remove_option(name=name, item={'ipasudoopt': item})

    def sudorule_add_host(self, name, item):
        return self._post_json(method='sudorule_add_host', name=name, item=item)

    def sudorule_add_host_host(self, name, item):
        return self.sudorule_add_host(name=name, item={'host': item})

    def sudorule_add_host_hostgroup(self, name, item):
        return self.sudorule_add_host(name=name, item={'hostgroup': item})

    def sudorule_remove_host(self, name, item):
        return self._post_json(method='sudorule_remove_host', name=name, item=item)

    def sudorule_remove_host_host(self, name, item):
        return self.sudorule_remove_host(name=name, item={'host': item})

    def sudorule_remove_host_hostgroup(self, name, item):
        return self.sudorule_remove_host(name=name, item={'hostgroup': item})

    def sudorule_add_allow_command(self, name, item):
        return self._post_json(method='sudorule_add_allow_command', name=name, item=item)

    def sudorule_remove_allow_command(self, name, item):
        return self._post_json(method='sudorule_remove_allow_command', name=name, item=item)

    def sudorule_add_user(self, name, item):
        return self._post_json(method='sudorule_add_user', name=name, item=item)

    def sudorule_add_user_user(self, name, item):
        return self.sudorule_add_user(name=name, item={'user': item})

    def sudorule_add_user_group(self, name, item):
        return self.sudorule_add_user(name=name, item={'group': item})

    def sudorule_remove_user(self, name, item):
        return self._post_json(method='sudorule_remove_user', name=name, item=item)

    def sudorule_remove_user_user(self, name, item):
        return self.sudorule_remove_user(name=name, item={'user': item})

    def sudorule_remove_user_group(self, name, item):
        return self.sudorule_remove_user(name=name, item={'group': item})


def get_sudorule_dict(cmdcategory=None, description=None, hostcategory=None, ipaenabledflag=None, usercategory=None):
    data = {}
    if cmdcategory is not None:
        data['cmdcategory'] = cmdcategory
    if description is not None:
        data['description'] = description
    if hostcategory is not None:
        data['hostcategory'] = hostcategory
    if ipaenabledflag is not None:
        data['ipaenabledflag'] = ipaenabledflag
    if usercategory is not None:
        data['usercategory'] = usercategory
    return data


def get_sudorule_diff(ipa_sudorule, module_sudorule):
    data = []
    for key in module_sudorule.keys():
        module_value = module_sudorule.get(key, None)
        ipa_value = ipa_sudorule.get(key, None)
        if isinstance(ipa_value, list) and not isinstance(module_value, list):
            module_value = [module_value]
        if isinstance(ipa_value, list) and isinstance(module_value, list):
            ipa_value = sorted(ipa_value)
            module_value = sorted(module_value)
        if ipa_value != module_value:
            data.append(key)
    return data


def modify_if_diff(module, name, ipa_list, module_list, add_method, remove_method):
    changed = False
    diff = list(set(ipa_list) - set(module_list))
    if len(diff) > 0:
        changed = True
        if not module.check_mode:
            for item in diff:
                remove_method(name=name, item=item)

    diff = list(set(module_list) - set(ipa_list))
    if len(diff) > 0:
        changed = True
        if not module.check_mode:
            for item in diff:
                add_method(name=name, item=item)

    return changed


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']
    cmd = module.params['cmd']
    host = module.params['host']
    hostcategory = module.params['hostcategory']
    hostgroup = module.params['hostgroup']
    ipaenabledflag = 'TRUE' if state in ['present', 'enabled'] else 'NO'
    sudoopt = module.params['sudoopt']
    user = module.params['user']
    usergroup = module.params['usergroup']

    module_sudorule = get_sudorule_dict(cmdcategory=module.params['cmdcategory'],
                                        description=module.params['description'],
                                        hostcategory=hostcategory,
                                        ipaenabledflag=ipaenabledflag,
                                        usercategory=module.params['usercategory'])
    ipa_sudorule = client.sudorule_find(name=name)

    changed = False
    if state in ['present', 'disabled', 'enabled']:
        if not ipa_sudorule:
            changed = True
            if not module.check_mode:
                ipa_sudorule = client.sudorule_add(name=name, item=module_sudorule)
        else:
            diff = get_sudorule_diff(ipa_sudorule, module_sudorule)
            if len(diff) > 0:
                changed = True
                if not module.check_mode:
                    if 'hostcategory' in diff:
                        if ipa_sudorule.get('memberhost_host', None) is not None:
                            client.sudorule_remove_host_host(name=name, item=ipa_sudorule.get('memberhost_host'))
                        if ipa_sudorule.get('memberhost_hostgroup', None) is not None:
                            client.sudorule_remove_host_hostgroup(name=name,
                                                                  item=ipa_sudorule.get('memberhost_hostgroup'))

                    client.sudorule_mod(name=name, item=module_sudorule)

        if cmd is not None:
            if not module.check_mode:
                client.sudorule_add_allow_command(name=name, item=cmd)

        if host is not None:
            if hostcategory is None and ipa_sudorule.get('hostcategory', None) == ['all'] and not module.check_mode:
                client.sudorule_mod(name=name, item={'hostcategory': None})

            changed = modify_if_diff(module, name, ipa_sudorule.get('memberhost_host', []), host,
                                     client.sudorule_add_host_host,
                                     client.sudorule_remove_host_host) or changed

        if hostgroup is not None:
            if hostcategory is None and ipa_sudorule.get('hostcategory', None) == ['all']:
                client.sudorule_mod(name=name, item={'hostcategory': None})
            changed = modify_if_diff(module, name, ipa_sudorule.get('memberhost_hostgroup', []), hostgroup,
                                     client.sudorule_add_host_hostgroup,
                                     client.sudorule_remove_host_hostgroup) or changed
        if sudoopt is not None:
            changed = modify_if_diff(module, name, ipa_sudorule.get('ipasudoopt', []), sudoopt,
                                     client.sudorule_add_option_ipasudoopt,
                                     client.sudorule_remove_option_ipasudoopt) or changed
        if user is not None:
            changed = modify_if_diff(module, name, ipa_sudorule.get('memberuser_user', []), user,
                                     client.sudorule_add_user_user,
                                     client.sudorule_remove_user_user) or changed
        if usergroup is not None:
            changed = modify_if_diff(module, name, ipa_sudorule.get('memberuser_group', []), usergroup,
                                     client.sudorule_add_user_group,
                                     client.sudorule_remove_user_group) or changed
    else:
        if ipa_sudorule:
            changed = True
            if not module.check_mode:
                client.sudorule_del(name)

    return changed, client.sudorule_find(name)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cmd=dict(type='list', required=False),
            cmdcategory=dict(type='str', required=False, choices=['all']),
            cn=dict(type='str', required=True, aliases=['name']),
            description=dict(type='str', required=False),
            host=dict(type='list', required=False),
            hostcategory=dict(type='str', required=False, choices=['all']),
            hostgroup=dict(type='list', required=False),
            sudoopt=dict(type='list', required=False),
            state=dict(type='str', required=False, default='present',
                       choices=['present', 'absent', 'enabled', 'disabled']),
            user=dict(type='list', required=False),
            usercategory=dict(type='str', required=False, choices=['all']),
            usergroup=dict(type='list', required=False),
            ipa_prot=dict(type='str', required=False, default='https', choices=['http', 'https']),
            ipa_host=dict(type='str', required=False, default='ipa.example.com'),
            ipa_port=dict(type='int', required=False, default=443),
            ipa_user=dict(type='str', required=False, default='admin'),
            ipa_pass=dict(type='str', required=True, no_log=True),
        ),
        mutually_exclusive=[['hostcategory', 'host'], ['hostcategory', 'hostgroup']],
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
