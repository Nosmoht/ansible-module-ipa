Ansible IPA modules
==========

__IMPORTANT__: A PR is opened to add these modules to ansible-extra-modules. Please use it to report issues. https://github.com/ansible/ansible-modules-extras/pull/3247.

- [Introduction](#introduction)
- [Usage](#usage)
 - [Group](#group)
 - [HBAC rule](#hbac_rule)
 - [Host](#host)
 - [Hostgroup](#hostgroup)
 - [Role](#role)
 - [Sudo command](#sudo_command)
 - [Sudo command group](#sudo_command_group)
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
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

Ensure group is absent
```yaml
- ipa_group:
    name: testgroup
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

## HBAC rule
```yaml
- name: Ensure rule to allow all users to access any host from any host
  ipa_hbacrule:
    name: allow_all
    description: Allow all users to access any host from any host
    hostcategory: all
    servicecategory: all
    usercategory: all
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

```yaml
- name:  Ensure rule with certain limitations
  ipa_hbacrule:
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
```

```yaml
- name: Ensure rule is absent
  ipa_hbacrule:
    name: rule_to_be_deleted
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

## Host
```yaml
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
```

```yaml
- name: ensure host without DNS record
  ipa_host:
    name: no-dns-record.example.com
    force: yes
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

```yaml
- name: ensure host is disabled
  ipa_host:
    name: host01.example.com
    state: disabled
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

```yaml
- name: ensure host is absent
  ipa_host:
    name: host01.example.com
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

## Hostgroup
```yaml
- name: Ensure hostgroup oracle-server is present
  ipa_hostgroup:
    name: oracle-server
    description: Oracle Database server
    host:
    - db01.example.com
    - db02.example.com
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

```yaml
- name: Ensure hostgroup oracle-server is absent
  ipa_hostgroup:
    name: oracle-server
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
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
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

```yaml
- name: Ensure role is absent
  ipa_role:
    name: Oracle Database Administrator
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

## Sudo command
```yaml
- name: Ensure sudo command exists
  ipa_sudocmd:
    name: date
    description: Date command
    state: present
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

```yaml
- name: Ensure sudo command does not exist
  ipa_sudocmd:
    name: date
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

## Sudo command group
```yaml
- name: Ensure sudo command group exists
  ipa_sudocmdgroup:
    name: cmd-group-01
    description: Command group 01
    sudocmd:
    - date
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

```yaml
- name: Ensure sudo command group does not exist
  ipa_sudocmdgroup:
    name: cmd-group-01
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

## Sudo rule
Ensure sudo rule is present thats allows all every body to execute any command
on any host without beeing asked for a password.
```yaml
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
```

Ensure user group developers can run every command on host group db-server as
well as on host db01.example.com.
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

Ensure sudo rule is absent
```yaml
- ipa_sudorule:
    name: sudo_all_nopasswd
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```


## User
Ensure a user is present
```yaml
- ipa_user:
    name: pinky
    state: present
    givenname: Pinky
    sn: Acme
    mail:
    - pinky@acme.com
    sshpubkey:
    - ssh-rsa ...
    - ssh-dss ...
    telephonenumber:
    - '+555123456'
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
```

Ensure a user is absent
```yaml
- ipa_user:
    name: brain
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
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
