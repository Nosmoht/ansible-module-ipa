Ansible IPA modules
==========

- [Introduction](#introduction)
- [Usage](#usage)

# Introduction
Ansible modules to manager IPA entries.

# Usage
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
