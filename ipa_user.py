#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: ipa_user
short_description: Manager IPA users
description:
- Add, modify and delete user within IPA server
options:
  displayname:
    description: Display name
    required: false
  givenname:
    description: First name
    required: false
  loginshell:
    description: Login shell
    required: false
  mail:
    description: Mail address
    required: false
  password:
    description: Password
    required: false
  sn:
    description: Surname
    required: false
  sshpubkeyfp:
    description: List of public SSH key
    required: false
  state:
    description: State to ensure
    required: false
    default: "present"
    choices: ["present", "absent", "enabled", "disabled"]
  telephonenumber:
    description: Telephone number
    required: false
  title:
    description: Title
    required: false
  uid:
    description: uid of the user
    required: true
    aliases: ["name"]
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
# Ensure pinky is present
- ipa_user:
    name: pinky
    state: present
    givenname: Pinky
    sn: Acme
    mail: pinky@acme.com
    telephonenumber: '+555123456'
    sshpubkeyfp:
    - ssh-rsa ....
    - ssh-dsa ....
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret

# Ensure brain is absent
- ipa_user:
    name: brain
    state: absent
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
'''

RETURN = '''
user:
  description: JSON data of user as returned by IPA
  returned: if found
  type: string
'''

import base64
import hashlib
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

    def user_find(self, name):
        return self._post_json(method='user_find', name=name, item={'all': True})

    def user_add(self, name, user):
        return self._post_json(method='user_add', name=name, item=user)

    def user_mod(self, name, user):
        return self._post_json(method='user_mod', name=name, item=user)

    def user_del(self, name):
        return self._post_json(method='user_del', name=name)

    def user_disable(self, name):
        return self._post_json(method='user_disable', name=name)

    def user_enable(self, name):
        return self._post_json(method='user_enable', name=name)


def get_user_dict(givenname=None, loginshell=None, mail=None, sn=None, sshpubkey=None, telephonenumber=None,
                  title=None):
    user = {}
    if givenname is not None:
        user['givenname'] = givenname
    if loginshell is not None:
        user['loginshell'] = loginshell
    if mail is not None:
        user['mail'] = sorted(mail)
    if sn is not None:
        user['sn'] = sn
    if sshpubkey is not None:
        user['ipasshpubkey'] = sorted(sshpubkey)
        sshpubkeyfp = []
        for pubkey in user['sshpubkey']:
            sshpubkeyfp.append(get_ssh_key_fingerprint(pubkey))
        user['sshpubkeyfp'] = sshpubkeyfp
    if telephonenumber is not None:
        user['telephonenumber'] = sorted(telephonenumber)
    if title is not None:
        user['title'] = title

    return user


def user_diff(ipa_user, module_user):
    """
        Return the keys of each dict whereas values are different. Unfortunately the IPA
        API returns everything as a list even if only a single value is possible.
        Therefore some more complexity is needed.
        The method will check if the value type of module_user.attr is not a list and
        create a list with that element if the same attribute in ipa_user is list. In this way i hope that the method
        must not be changed if the returned API dict is changed.
    :param ipa_user:
    :param module_user:
    :return:
    """
    #    return [item for item in module_user.keys() if module_user.get(item, None) != ipa_user.get(item, None)]
    result = []
    # Remove the ipasshpubkey element as it is not returned from IPA. IPA returns the fingerprint of each key instead.
    module_user = {key: module_user[key] for key in module_user if key != 'ipasshpubkey'}
    for key in module_user:
        mod_value = module_user.get(key, None)
        ipa_value = ipa_user.get(key, None)
        if isinstance(ipa_value, list) and not isinstance(mod_value, list):
            mod_value = [mod_value]
        if mod_value != ipa_value:
            result.append(key)
    return result


def get_ssh_key_fingerprint(ssh_key):
    """
    Return the public key fingerprint of a given public SSH key in format "FB:0C:AC:0A:07:94:5B:CE:75:6E:63:32:13:AD:AD:D7 (ssh-rsa)"
    :param ssh_key:
    :return:
    """
    parts = ssh_key.strip().split()
    if len(parts) == 0:
        return None
    key_type = parts[0]
    key = base64.b64decode(parts[1].encode('ascii'))

    fp_plain = hashlib.md5(key).hexdigest()
    return ':'.join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2])).upper() + ' (%s)' % key_type


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']

    module_user = get_user_dict(givenname=module.params.get('givenname'), loginshell=module.params['loginshell'],
                                mail=module.params['mail'], sn=module.params['sn'],
                                sshpubkey=module.params['sshpubkey'],
                                telephonenumber=module.params['telephonenumber'], title=module.params['title'])

    ipa_user = client.user_find(name=name)

    if not ipa_user:
        if state in ['present', 'enabled', 'disabled']:
            if module.check_mode:
                module.exit_json(changed=True, user=module_user)

            # sshpubkeyfp must not be part of the dictionary but is added to make comparison of existing users eaiser by
            # method get_user_dict, so it needs to be removed. Otherwise the IPA API responds: Unknown option: sshpubkeyfp"
            if 'sshpubkeyfp' in module_user: del module_user['sshpubkeyfp']
            client.user_add(name, module_user)

            if state == 'enabled':
                client.user_enable(name=name)
            if state == 'disable':
                client.user_disable(name=name)
            return True, client.user_find(name=name)
    else:
        if state in ['present', 'enabled', 'disabled']:
            diff = user_diff(ipa_user, module_user)
            if len(diff) > 0:
                if module.check_mode:
                    module.exit_json(changed=True, user=ipa_user)
                client.user_mod(name=name, user=module_user)
                return True, client.user_find(name=name)
        if state == 'absent':
            if module.check_mode:
                module.exit_json(changed=True, user=ipa_user)

            client.user_del(name)
            return True, None
    return False, ipa_user


def main():
    module = AnsibleModule(
        argument_spec=dict(
            displayname=dict(type='str', required=False),
            givenname=dict(type='str', required=False),
            loginshell=dict(type='str', required=False),
            mail=dict(type='list', required=False),
            sn=dict(type='str', required=False),
            uid=dict(type='str', required=True, aliases=['name']),
            password=dict(type='str', required=False, no_log=True),
            sshpubkey=dict(type='list', required=False),
            state=dict(type='str', required=False, default='present',
                       choices=['present', 'absent', 'enabled', 'disabled']),
            telephonenumber=dict(type='list', required=False),
            title=dict(type='str', required=False),
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

    # If sshpubkey is defined as None than module.params['sshpubkey'] is [None]. IPA itself returns None (not a list).
    # Therefore a small check here to replace list(None) by None. Otherwise the user_diff method would return sshpubkey
    # as different which should be avoided.
    if module.params['sshpubkey'] is not None:
        if len(module.params['sshpubkey']) == 1 and module.params['sshpubkey'][0] is "":
            module.params['sshpubkey'] = None

    try:
        client.login()
        changed, user = ensure(module, client)
        module.exit_json(changed=changed, user=user)
    except Exception as e:
        module.fail_json(msg=e.message)


if __name__ == '__main__':
    main()
