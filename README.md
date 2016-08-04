Ansible IPA modules
==========

- [Introduction](#introduction)
- [Usage](#usage)
 - [Group](#group)
 - [Hostgroup](#hostgroup)
 - [Role](#role)
 - [Sudo rule](#sudo_rule)
 - [User](#user)
- [License](#license)
- [Author](#author)

# Introduction
Ansible modules to manager IPA entries.

# Usage

## Group
Ensure a group is present
```yaml
- ipa_group:
    name: oinstall
    description: Oracle software owner
    gidnumber: 54321
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

Ensure group is absent
```yaml
- ipa_group:
    name: testgroup
    state: absent
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

## Hostgroup
```yaml
- name: Ensure hostgroup oracle-server is present
  ipa_hostgroup:
    name: oracle-server
    description: Oracle Database server
    state: present
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

```yaml
- name: Ensure hostgroup oracle-server is absent
  ipa_hostgroup:
    name: oracle-server
    state: present
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

## Role
```yaml
- name: Ensure role is present
  ipa_role:
    name: Oracle Database Administrator
    description: Responsible for administrating Oracle Databases
    state: present
    user:
    - pinky
    - brain
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

```yaml
- name: Ensure role is absent
  ipa_role:
    name: Oracle Database Administrator
    state: absent
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

## Sudo rule
Ensure sudo rule is present thats allows all members of group ipausers as well as user pinky
to run every command on every hosts with sudo without being asked for a password.
```yaml
- ipa_sudorule:
    name: sudo_all_nopasswd
    cmdcategory: all
    description: Allow to run every command with sudo without password
    hostcategory: all
    sudoopt: '!authenticate'
    groups:
    - ipausers
    users:
    - pinky
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

Ensure sudo rule is absent
```yaml
- ipa_sudorule:
    name: sudo_all_nopasswd
    state: absent
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```


## User
Ensure a user is present
```yaml
- ipa_user:
    name: pinky
    state: present
    givenname: Pinky
    sn: Acme
    mail: pinky@acme.com
    sshpubkey:
    - ssh-rsa ...
    - ssh-dss ...
    telephonenumber: '+555123456'
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

Ensure a user is absent
```yaml
- ipa_user:
    name: brain
    state: absent
    ip_host: ipa.example.com
    ip_user: admin
    ip_pass: topsecret
```

# License

Copyright 2016 Thomas Krahn

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Author
[Thomas Krahn]

[Thomas Krahn]: mailto:ntbc@gmx.net
