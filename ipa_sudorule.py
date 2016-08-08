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

    def sudorule_add(self, name, sudorule):
        return self._post_json(method='sudorule_add', name=name, item=sudorule)

    def sudorule_add_option(self, name, ipasudoopt):
        data = {'ipasudoopt': ipasudoopt}
        return self._post_json(method='sudorule_add_option', name=name, item=data)

    def sudorule_add_host(self, name, host):
        data = {'host': host}
        return self._post_json(method='sudorule_add_host', name=name, item=data)

    def sudorule_add_allow_command(self, name, cmd):
        data = {'sudocmd': cmd}
        return self._post_json(method='sudorule_add_allow_command', name=name, item=data)

    def sudorule_mod(self, name, item):
        return self._post_json(method='sudorule_mod', name=name, item=item)

    def sudorule_add_user(self, name, sudorule):
        return self._post_json(method='sudorule_add_user', name=name, item=sudorule)

    def sudorule_del(self, uid):
        return self._post_json(method='sudorule_del', name=uid)


def get_sudorule_dict(description=None, ipaenabledflag=None):
    data = {}
    if description is not None:
        data['description'] = description
    if ipaenabledflag is not None:
        data['ipaenabledflag'] = ipaenabledflag
    return data


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']
    cmd = module.params['cmd']
    cmdcategory = module.params['cmdcategory']
    groups = module.params['groups']
    host = module.params['host']
    hostcategory = module.params['hostcategory']
    ipaenabledflag = state in ['present', 'enabled']
    ipasudooptions = module.params['sudoopt']
    users = module.params['users']

    module_sudorule = get_sudorule_dict(description=module.params['description'], ipaenabledflag=ipaenabledflag)
    ipa_sudorule = client.sudorule_find(name=name)

    if not ipa_sudorule:
        if state in ['present', 'disabled', 'enabled']:
            if module.check_mode:
                return True, None

            client.sudorule_add(name=name, sudorule=module_sudorule)

            if ipasudooptions is not None:
                for sudooption in ipasudooptions:
                    client.sudorule_add_option(name=name, ipasudoopt=sudooption)

            if users is not None:
                client.sudorule_add_user(name=name, users=users)

            if groups is not None:
                client.sudorule_add_user(name=name, groups=groups)

            if hostcategory is not None:
                client.sudorule_mod(name=name, item={'hostcategory': hostcategory})

            if host is not None:
                client.sudorule_add_host(name=name, hosts=host)

            if cmdcategory is not None:
                client.sudorule_mod(name=name, item={'cmdcategory': cmdcategory})

            if cmd is not None:
                client.sudorule_add_allow_command(name=name, cmd=cmd)

            return True, client.sudorule_find(name)
    else:
        if state == 'absent':
            if module.check_mode:
                return True, ipa_sudorule

            client.sudorule_del(name)
            return True, None

        changed=False
    return False, ipa_sudorule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cmdcategory=dict(type='str', required=False),
            cmd=dict(type='list', required=False),
            cn=dict(type='str', required=True, aliases=['name']),
            description=dict(type='str', required=False),
            groups=dict(type='list', required=False),
            hostcategory=dict(type='str', required=False),
            host=dict(type='list', required=False),
            sudoopt=dict(type='list', required=False),
            state=dict(type='str', required=False, default='present',
                       choices=['present', 'absent', 'enabled', 'disabled']),
            users=dict(type='str', required=False),
            ipa_prot=dict(type='str', required=False, default='https', choices=['http', 'https']),
            ipa_host=dict(type='str', required=False, default='ipa.example.com'),
            ipa_port=dict(type='int', required=False, default=443),
            ipa_user=dict(type='str', required=False, default='admin'),
            ipa_pass=dict(type='str', required=True, no_log=True),
        ),
        mutually_exclusive=[['cmd', 'cmdcategory'], ['host', 'hostcategory']],
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
