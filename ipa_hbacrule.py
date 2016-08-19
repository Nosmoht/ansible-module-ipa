#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_hbacrule
author: Thomas Krahn (@Nosmoht)
short_description: Manager IPA HBAC rule
description:
- Add, modify or delete an IPA HBAC rule using IPA API.
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
    - List of host names to assign.
    - If an empty list is passed all hosts will be removed from the rule.
    - If option is omitted hosts will not be checked or changed.
    required: false
  hostcategory:
    description: Host category
    required: false
  hostgroup:
    description:
    - List of hostgroup names to assign.
    - If an empty list is passed all hostgroups will be removed. from the rule
    - If option is omitted hostgroups will not be checked or changed.
  service:
    description:
    - List of service names to assign.
    - If an empty list is passed all services will be removed from the rule.
    - If option is omitted services will not be checked or changed.
  servicecategory:
    description: Service category
  servicegroup:
    description:
    - List of service group names to assign.
    - If an empty list is passed all assigned service groups will be removed from the rule.
    - If option is omitted service groups will not be checked or changed.
  sourcehost:
    description:
    - List of source host names to assign.
    - If an empty list if passed all assigned source hosts will be removed from the rule.
    - If option is omitted source hosts will not be checked or changed.
  sourcehostcategory:
    description: Source host category
  sourcehostgroup:
    description:
    - List of source host group names to assign.
    - If an empty list if passed all assigned source host groups will be removed from the rule.
    - If option is omitted source host groups will not be checked or changed.
  state:
    description: State to ensure
    required: false
    default: "present"
    choices: ["present", "absent", "enabled", "disabled"]
  user:
    description:
    - List of user names to assign.
    - If an empty list if passed all assigned users will be removed from the rule.
    - If option is omitted users will not be checked or changed.
  usercategory:
    description: User category
  usergroup:
    description:
    - List of user group names to assign.
    - If an empty list if passed all assigned user groups will be removed from the rule.
    - If option is omitted user groups will not be checked or changed.
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
- json
- requests
'''

EXAMPLES = '''
# Ensure rule to allow all users to access any host from any host
- ipa_hbacrule:
    name: allow_all
    description: Allow all users to access any host from any host
    hostcategory: all
    servicecategory: all
    usercategory: all
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

# Ensure rule with certain limitations
- ipa_hbacrule:
    name: allow_all_developers_access_to_db
    description: Allow all developers to access any database from any host
    hostgroup:
    - db-server
    usergroup:
    - developers
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

# Ensure rule is absent
- ipa_hbacrule:
    name: rule_to_be_deleted
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
'''

RETURN = '''
hbacrule:
  description: Dictionary describing the HBAC rule as returned by IPA
  returned: On success if I(state) is one of 'present', 'enabled' or 'disabled'
  type: dictionary
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

    def hbacrule_find(self, name):
        return self._post_json(method='hbacrule_find', name=None, item={'all': True, 'cn': name})

    def hbacrule_add(self, name, item):
        return self._post_json(method='hbacrule_add', name=name, item=item)

    def hbacrule_mod(self, name, item):
        return self._post_json(method='hbacrule_mod', name=name, item=item)

    def hbacrule_del(self, name):
        return self._post_json(method='hbacrule_del', name=name)

    def hbacrule_add_host(self, name, item):
        return self._post_json(method='hbacrule_add_host', name=name, item=item)

    def hbacrule_remove_host(self, name, item):
        return self._post_json(method='hbacrule_remove_host', name=name, item=item)

    def hbacrule_add_service(self, name, item):
        return self._post_json(method='hbacrule_add_service', name=name, item=item)

    def hbacrule_remove_service(self, name, item):
        return self._post_json(method='hbacrule_remove_service', name=name, item=item)

    def hbacrule_add_user(self, name, item):
        return self._post_json(method='hbacrule_add_user', name=name, item=item)

    def hbacrule_remove_user(self, name, item):
        return self._post_json(method='hbacrule_remove_user', name=name, item=item)

    def hbacrule_add_sourcehost(self, name, item):
        return self._post_json(method='hbacrule_add_sourcehost', name=name, item=item)

    def hbacrule_remove_sourcehost(self, name, item):
        return self._post_json(method='hbacrule_remove_sourcehost', name=name, item=item)


def get_hbacrule_dict(description=None, hostcategory=None, ipaenabledflag=None, servicecategory=None,
                      sourcehostcategory=None,
                      usercategory=None):
    data = {}
    if description is not None:
        data['description'] = description
    if hostcategory is not None:
        data['hostcategory'] = hostcategory
    if ipaenabledflag is not None:
        data['ipaenabledflag'] = ipaenabledflag
    if servicecategory is not None:
        data['servicecategory'] = servicecategory
    if sourcehostcategory is not None:
        data['sourcehostcategory'] = sourcehostcategory
    if usercategory is not None:
        data['usercategory'] = usercategory
    return data


def get_hbcarule_diff(ipa_hbcarule, module_hbcarule):
    data = []
    compareable_keys = ['description', 'hostcategory', 'servicecategory', 'sourcehostcategory', 'usercategory']
    for key in compareable_keys:
        module_value = module_hbcarule.get(key, None)
        if module_value is None:
            continue
        ipa_value = ipa_hbcarule.get(key, None)
        if isinstance(ipa_value, list) and not isinstance(module_value, list):
            module_value = [module_value]
        if isinstance(ipa_value, list) and isinstance(module_value, list):
            ipa_value = sorted(ipa_value)
            module_value = sorted(module_value)
        if ipa_value != module_value:
            data.append(key)
    return data


def modify_if_diff(module, name, ipa_list, module_list, add_method, remove_method, item):
    changed = False
    diff = list(set(ipa_list) - set(module_list))
    if len(diff) > 0:
        changed = True
        if not module.check_mode:
            remove_method(name=name, item={item: diff})

    # Hosts that a not port of the group but should must be added
    diff = list(set(module_list) - set(ipa_list))
    if len(diff) > 0:
        changed = True
        if not module.check_mode:
            add_method(name=name, item={item: diff})

    return changed


def ensure(module, client):
    name = module.params['name']
    state = module.params['state']
    ipaenabledflag = state in ['present', 'enabled']
    host = module.params['host']
    hostcategory = module.params['hostcategory']
    hostgroup = module.params['hostgroup']
    service = module.params['service']
    servicecategory = module.params['servicecategory']
    servicegroup = module.params['servicegroup']
    sourcehost = module.params['sourcehost']
    sourcehostcategory = module.params['sourcehostcategory']
    sourcehostgroup = module.params['sourcehostgroup']
    user = module.params['user']
    usercategory = module.params['usercategory']
    usergroup = module.params['usergroup']

    module_hbacrule = get_hbacrule_dict(description=module.params['description'],
                                        hostcategory=hostcategory,
                                        ipaenabledflag=ipaenabledflag,
                                        servicecategory=servicecategory,
                                        sourcehostcategory=sourcehostcategory,
                                        usercategory=usercategory)
    ipa_hbacrule = client.hbacrule_find(name=name)

    changed = False
    if state in ['present', 'enabled', 'disabled']:
        if not ipa_hbacrule:
            changed = True
            if not module.check_mode:
                client.hbacrule_add(name=name, item=module_hbacrule)
                ipa_hbacrule = client.hbacrule_find(name=name)
        else:
            diff = get_hbcarule_diff(ipa_hbacrule, module_hbacrule)
            if len(diff) > 0:
                changed = True
                if not module.check_mode:
                    client.hbcarule_mod(name=name, item=module_hbacrule)

        if host is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('memberhost_host', []), host,
                                     client.hbacrule_add_host,
                                     client.hbacrule_remove_host, 'host') or changed

        if hostgroup is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('memberhost_hostgroup', []), hostgroup,
                                     client.hbacrule_add_host,
                                     client.hbacrule_remove_host, 'hostgroup') or changed

        if service is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('memberservice_hbacsvc', []), service,
                                     client.hbacrule_add_service,
                                     client.hbacrule_remove_service, 'hbacsvc') or changed

        if servicegroup is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('memberservice_hbacsvcgroup', []),
                                     servicegroup,
                                     client.hbacrule_add_service,
                                     client.hbacrule_remove_service, 'hbacsvcgroup') or changed

        if sourcehost is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('sourcehost_host', []), sourcehost,
                                     client.hbacrule_add_sourcehost,
                                     client.hbacrule_remove_sourcehost, 'host') or changed

        if sourcehostgroup is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('sourcehost_group', []), sourcehostgroup,
                                     client.hbacrule_add_sourcehost,
                                     client.hbacrule_remove_sourcehost, 'hostgroup') or changed

        if user is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('memberuser_user', []), user,
                                     client.hbacrule_add_user,
                                     client.hbacrule_remove_user, 'user') or changed

        if usergroup is not None:
            changed = modify_if_diff(module, name, ipa_hbacrule.get('memberuser_group', []), usergroup,
                                     client.hbacrule_add_user,
                                     client.hbacrule_remove_user, 'group') or changed
    else:
        if ipa_hbacrule:
            changed = True
            if not module.check_mode:
                client.hbacrule_del(name=name)

    return changed, client.hbacrule_find(name=name)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cn=dict(type='str', required=True, aliases=['name']),
            description=dict(type='str', required=False),
            host=dict(type='list', required=False),
            hostcategory=dict(type='str', required=False),
            hostgroup=dict(type='list', required=False),
            service=dict(type='list', required=False),
            servicecategory=dict(type='str', required=False),
            servicegroup=dict(type='list', required=False),
            sourcehost=dict(type='list', required=False),
            sourcehostcategory=dict(type='str', required=False),
            sourcehostgroup=dict(type='list', required=False),
            state=dict(type='str', required=False, default='present',
                       choices=['present', 'absent', 'enabled', 'disabled']),
            user=dict(type='list', required=False),
            usercategory=dict(type='str', required=False),
            usergroup=dict(type='list', required=False),
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
        changed, hbacrule = ensure(module, client)
        module.exit_json(changed=changed, hbacrule=hbacrule)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
