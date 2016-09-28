#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_host
short_description: Manager IPA host
description:
- Add, modify and delete an IPA host using IPA API
options:
  fqdn:
    description:
    - Full qualified domain name.
    - Can not be changed as it is the unique identifier.
    required: true
    aliases: ["name"]
  description:
    description: A description of this host
    required: false
  force:
    description: Force host name even if not in DNS
    required: false
  ip_address:
    description: Add the host to DNS with this IP address
    required: false
  nshostlocation:
    description: Host location (e.g. "Lab 2")
    required: false
  nshardwareplatform:
    description: Host hardware platform (e.g. "Lenovo T61")
    required: false
  nsosversion:
    description: Host operating system and version (e.g. "Fedora 9")
    required: false
  usercertificate:
    description: Base-64 encoded server certificate
    required: false
  macddress:
    description: Hardware MAC address(es) on this host
    required: false
  state:
    description: State to ensure
    required: false
    default: "present"
    choices: ["present", "absent", "disabled"]
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
- name: ensure host is present
  ipa_host:
    name: host01.example.com
    description: Example host
    ip_address: 192.168.0.123
    nshostlocation: Lab
    nsosversion: CentOS 7
    nshardwareplatform: Lenovo T61
    macaddress:
    - "08:00:27:E3:B1:2D"
    - "52:54:00:BD:97:1E"
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

- name: ensure host is disabled
  ipa_host:
    name: host01.example.com
    state: disabled
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

- name: ensure host is absent
  ipa_host:
    name: host01.example.com
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
'''

RETURN = '''
host:
  description: JSON data of the host as returned by IPA
  returned: if found
  type: string
host_diff:
  description: List of options that differ and would be changed
  returned: if check mode and a difference is found
  type: list
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

    def host_find(self, name):
        return self._post_json(method='host_find', name=None, item={'all': True, 'fqdn': name})

    def host_add(self, name, host):
        return self._post_json(method='host_add', name=name, item=host)

    def host_mod(self, name, host):
        return self._post_json(method='host_mod', name=name, item=host)

    def host_del(self, name):
        return self._post_json(method='host_del', name=name)

    def host_disable(self, name):
        return self._post_json(method='host_disable', name=name)


def get_host_dict(description=None, force=None, ip_address=None, nshostlocation=None, nshardwareplatform=None,
                  nsosversion=None, usercertificate=None, macaddress=None):
    data = {}
    if description is not None:
        data['description'] = description
    if force is not None:
        data['force'] = force
    if ip_address is not None:
        data['ip_address'] = ip_address
    if nshostlocation is not None:
        data['nshostlocation'] = nshostlocation
    if nshardwareplatform is not None:
        data['nshardwareplatform'] = nshardwareplatform
    if nsosversion is not None:
        data['nsosversion'] = nsosversion
    if usercertificate is not None:
        data['usercertificate'] = [{"__base64__": item} for item in usercertificate]
    if macaddress is not None:
        data['macaddress'] = macaddress
    return data


def get_host_diff(ipa_host, module_host):
    non_updateable_keys = ['force', 'ip_address']
    data = []
    for key in non_updateable_keys:
        if key in module_host:
            del module_host[key]
    for key in module_host.keys():
        ipa_value = ipa_host.get(key, None)
        module_value = module_host.get(key, None)
        if isinstance(ipa_value, list) and not isinstance(module_value, list):
            module_value = [module_value]
        if isinstance(ipa_value, list) and isinstance(module_value, list):
            ipa_value = sorted(ipa_value)
            module_value = sorted(module_value)
        if ipa_value != module_value:
            data.append(key)
    return data


def ensure(module, client):
    name = module.params['name']
    state = module.params['state']

    ipa_host = client.host_find(name=name)
    module_host = get_host_dict(description=module.params['description'],
                                force=module.params['force'], ip_address=module.params['ip_address'],
                                nshostlocation=module.params['nshostlocation'],
                                nshardwareplatform=module.params['nshardwareplatform'],
                                nsosversion=module.params['nsosversion'],
                                usercertificate=module.params['usercertificate'],
                                macaddress=module.params['macaddress'])
    changed = False
    if state in ['present', 'enabled', 'disabled']:
        if not ipa_host:
            changed = True
            if not module.check_mode:
                ipa_host = client.host_add(name=name, host=module_host)
        else:
            diff = get_host_diff(ipa_host, module_host)
            if len(diff) > 0:
                changed = True
                if not module.check_mode:
                    ipa_host = client.host_mod(name=name, host={key: module_host.get(key) for key in diff})

    else:
        if ipa_host:
            changed = True
            if not module.check_mode:
                client.host_del(name=name)

    return changed, ipa_host


def main():
    module = AnsibleModule(
        argument_spec=dict(
            description=dict(type='str', required=False),
            fqdn=dict(type='str', required=True, aliases=['name']),
            force=dict(type='bool', required=False),
            ip_address=dict(type='str', required=False),
            nshostlocation=dict(type='str', required=False),
            nshardwareplatform=dict(type='str', required=False),
            nsosversion=dict(type='str', required=False),
            usercertificate=dict(type='list', required=False),
            macaddress=dict(type='list', required=False),
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
        changed, host = ensure(module, client)
        module.exit_json(changed=changed, host=host)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
