Ansible IPA modules
==========

- [Introduction](#introduction)
- [Usage](#usage)
 - [Sudo rule](#sudo_rule)
 - [User](#user)

# Introduction
Ansible modules to manager IPA entries.

# Usage

## Sudo rule
Ensure sudo rule is present
```yaml
- ipa_sudorule:
    name: sudo_all_nopasswd
    description: Allow to run every command with sudo without password
    sudoopt: '!authenticate'
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
