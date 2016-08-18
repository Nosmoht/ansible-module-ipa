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
        return self._post_json(method='sudorule_find', name=name, item={'all': True})

    def sudorule_add(self, name, item):
        return self._post_json(method='sudorule_add', name=name, item=item)

    def sudorule_mod(self, name, item):
        return self._post_json(method='sudorule_mod', name=name, item=item)

    def sudorule_del(self, name):
        return self._post_json(method='sudorule_del', name=name)

    def sudorule_add_option(self, name, item):
        return self._post_json(method='sudorule_add_option', name=name, item=item)

    def sudorule_remove_option(self, name, item):
        return self._post_json(method='sudorule_remove_option', name=name, item=item)

    def sudorule_add_host(self, name, item):
        return self._post_json(method='sudorule_add_host', name=name, item=item)

    def sudorule_remove_host(self, name, item):
        return self._post_json(method='sudorule_add_host', name=name, item=item)

    def sudorule_add_allow_command(self, name, item):
        return self._post_json(method='sudorule_add_allow_command', name=name, item=item)

    def sudorule_remove_allow_command(self, name, item):
        return self._post_json(method='sudorule_remove_allow_command', name=name, item=item)

    def sudorule_add_user(self, name, item):
        return self._post_json(method='sudorule_add_user', name=name, item=item)

    def sudorule_remove_user(self, name, item):
        return self._post_json(method='sudorule_remove_user', name=name, item=item)


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
    compareable_keys = ['cmdcategory', 'description', 'hostcategory']
    for key in compareable_keys:
        ipa_value = ipa_sudorule.get(key, None)
        module_value = module_sudorule.get(key, None)
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
            for diff_item in diff:
                remove_method(name=name, item={item: diff_item})

    # Hosts that a not port of the group but should must be added
    diff = list(set(module_list) - set(ipa_list))
    if len(diff) > 0:
        changed = True
        if not module.check_mode:
            for diff_item in diff:
                add_method(name=name, item={item: diff_item})

    return changed


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']
    cmd = module.params['cmd']
    host = module.params['host']
    hostgroup = module.params['hostgroup']
    ipaenabledflag = state in ['present', 'enabled']
    sudoopt = module.params['sudoopt']
    user = module.params['user']
    usergroup = module.params['usergroup']

    module_sudorule = get_sudorule_dict(cmdcategory=module.params['cmdcategory'],
                                        description=module.params['description'],
                                        hostcategory=module.params['hostcategory'],
                                        ipaenabledflag=ipaenabledflag,
                                        usercategory=module.params['usercategory'])
    ipa_sudorule = client.sudorule_find(name=name)

    changed = False
    if state in ['present', 'disabled', 'enabled']:
        if not ipa_sudorule:
            changed = True
            if not module.check_mode:
                client.sudorule_add(name=name, item=module_sudorule)
        else:
            diff = get_sudorule_diff(ipa_sudorule, module_sudorule)
            if len(diff) > 0:
                changed = True
                if not module.check_mode:
                    client.sudorule_mod(name=name, item=module_sudorule)

        if cmd is not None:
            client.sudorule_add_allow_command(name=name, item=cmd)

        if host is not None:
            changed = changed or modify_if_diff(module, name, ipa_sudorule.get('memberhost_host', []), host,
                                                client.sudorule_add_host,
                                                client.sudorule_remove_host, 'host')
        if hostgroup is not None:
            changed = changed or modify_if_diff(module, name, ipa_sudorule.get('memberhost_group', []), hostgroup,
                                                client.sudorule_add_host,
                                                client.sudorule_remove_host, 'hostgroup')
        if sudoopt is not None:
            changed = changed or modify_if_diff(module, name, ipa_sudorule.get('ipasudoopt', []), sudoopt,
                                                client.sudorule_add_option,
                                                client.sudorule_remove_option, 'ipasudoopt')
        if user is not None:
            changed = changed or modify_if_diff(module, name, ipa_sudorule.get('memberuser_user', []), user,
                                                client.sudorule_add_user,
                                                client.sudorule_remove_user, 'user')
        if usergroup is not None:
            changed = changed or modify_if_diff(module, name, ipa_sudorule.get('memberuser_group', []), usergroup,
                                                client.sudorule_add_user,
                                                client.sudorule_remove_user, 'group')
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
