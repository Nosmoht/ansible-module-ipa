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

    def find_user(self, name):
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())
        data = {'method': 'user_find', 'params': [[name], {}], 'id': 0}

        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, cookies=self.cookies, verify=False)
            r.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error on post user_find request: {}'.format(e.message))

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self.module.fail_json(msg='error in user_find response: {}'.format(err))

        return resp.get('result').get('result')

    def add_user(self, uid, givenname=None, loginshell=None, mail=None, sn=None, sshpubkeyfp=None, telephonenumber=None,
                 title=None):
        user = {}
        if givenname is not None:
            user['givenname'] = givenname
        if loginshell is not None:
            user['loginshell'] = loginshell
        if mail is not None:
            user['mail'] = mail
        if sn is not None:
            user['sn'] = sn
        if sshpubkeyfp is not None:
            user['ipasshpubkey'] = sshpubkeyfp
        if telephonenumber is not None:
            user['telephonenumber'] = telephonenumber
        if title is not None:
            user['title'] = title

        data = {'method': 'user_add', 'params': [[uid], user]}
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())

        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, verify=False, cookies=self.cookies)
            r.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error while posting user_add request: {}'.format(e.message))

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self.module.fail_json(msg=err)

    def del_user(self, uid):
        data = {'method': 'user_del', 'params': [[uid], {}]}
        url = '{base_url}/session/json'.format(base_url=self.get_base_url())

        try:
            r = requests.post(url=url, data=json.dumps(data), headers=self.headers, verify=False, cookies=self.cookies)
            r.raise_for_status()
        except Exception as e:
            self.module.fail_json(msg='error while posting user_del request: {}'.format(e.message))

        resp = json.loads(r.content)
        err = resp.get('error')
        if err is not None:
            self.module.fail_json(msg='error in user_del response: {}'.format(err))


def ensure(module, client):
    state = module.params['state']
    name = module.params['name']

    user = client.find_user(name=name)
    if not user:
        if state == 'present':
            client.add_user(name, givenname=module.params.get('givenname'), loginshell=module.params['loginshell'],
                            mail=module.params['mail'], sn=module.params['sn'],
                            sshpubkeyfp=module.params['sshpubkeyfp'],
                            telephonenumber=module.params['telephonenumber'], title=module.params['title'])
            return True, client.find_user(name=name)
    else:
        if state == 'absent':
            client.del_user(name)
            return True, None
    return False, user


def main():
    module = AnsibleModule(
        argument_spec=dict(
            displayname=dict(type='str', required=False),
            givenname=dict(type='str', required=False),
            loginshell=dict(type='str', required=False),
            mail=dict(type='str', required=False),
            sn=dict(type='str', required=False),
            uid=dict(type='str', required=True, aliases=['name']),
            password=dict(type='str', required=False, no_log=True),
            sshpubkeyfp=dict(type='list', required=False),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            telephonenumber=dict(type='str', required=False),
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
    try:
        client.login()
        changed, user = ensure(module, client)
        module.exit_json(changed=changed, user=user)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
