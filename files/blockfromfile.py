#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Evan Kaufman <evan@digitalflophouse.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = """
---
module: blockfromfile
author: "Evan Kaufman (@EvanK)"
version_added: "2.0"
short_description: Search file from remote node using a provided regular expression.
description:
  - This module will search a remote file for all instances of a pattern.
    Effectively the inverse of M(replace).
options:
  src:
    required: true
    aliases: [ name, srcfile ]
    description:
      - The file to search.
  regexp:
    required: true
    description:
      - The regular expression to look for in the contents of the file.
        Uses Python regular expressions; see
        U(http://docs.python.org/2/library/re.html).
        Uses multiline mode, which means C(^) and C($) match the beginning
        and end respectively of I(each line) of the file.
  fail_on_missing:
    required: false
    default: false
    description:
      - Makes it fails when the source file is missing.
notes:
   - "See also: M(replace)"
"""

EXAMPLES = r"""
ansible host -m blockfromfile -a 'src=/etc/keepalived/keepalived.conf regexp="^[ \t\f\v]*priority[ \t\f\v]*(?P<priority>\d+)[ \t\f\v]*"'
    host | success >> {
        "changed": true, 
        "matches": [
            {
                "groups": [
                    "100"
                ], 
                "named_groups": {
                    "priority": "100"
                }
            }
        ], 
        "msg": "Found 1 matches in /etc/keepalived/keepalived.conf"
    }

ansible host -m blockfromfile -a 'src=/etc/hosts regexp="^[ \t\f\v]*(?P<address>[\d.:]+)[ \t\f\v]*(?P<hostnames>(?:\S+[ \t\f\v]*)+)"'
    host | success >> {
        "changed": true, 
        "matches": [
            {
                "groups": [
                    "127.0.0.1", 
                    "localhost.localdomain localhost"
                ], 
                "named_groups": {
                    "address": "127.0.0.1", 
                    "hostnames": "localhost.localdomain localhost"
                }
            }, 
            {
                "groups": [
                    "::1", 
                    "ip6-localhost ip6-loopback"
                ], 
                "named_groups": {
                    "address": "::1", 
                    "hostnames": "ip6-localhost ip6-loopback"
                }
            }, 
        ], 
        "msg": "Found 2 matches in /etc/hosts"
    }

ansible host -m blockfromfile -a 'src=/etc/sudoers regexp="^(\S+)(?:[ \t\f\v]*\s+)*NOPASSWD:ALL"'
    host | success >> {
        "changed": false, 
        "msg": "Found no matches in /etc/sudoers"
    }
"""

import re
import os

def main():
    module = AnsibleModule(
        argument_spec=dict(
            src=dict(required=True, aliases=['name', 'srcfile']),
            regexp=dict(required=True),
            fail_on_missing=dict(required=False, default=False, type='bool'),
        ),
        supports_check_mode=True
    )

    params = module.params
    src = os.path.expanduser(params['src'])

    if os.path.isdir(src):
        module.fail_json(rc=256, msg='Source %s is a directory !' % src)

    if not os.path.exists(src):
        if params['fail_on_missing']:
            module.fail_json(rc=255, msg='Source %s does not exist !' % src)
        else:
            module.exit_json(changed=False, msg='Source %s does not exist !' % src)
    else:
        try:
            f = open(src, 'rb')
            contents = f.read()
            f.close()
        except IOError, err:
            module.fail_json(rc=254, msg='Source %s could not be read: %s' % (src, err.strerror))

    result = []
    found  = re.finditer(params['regexp'], contents, re.MULTILINE)

    for match in found:
        result.append({
            'groups': match.groups(),
            'named_groups': match.groupdict(),
        })

    if result:
        module.exit_json(matches=result, changed=True, msg='Found %d matches in %s' % (len(result), src))
    else:
        module.exit_json(changed=False, msg='Found no matches in %s' % src)

# common module boilerplate
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
