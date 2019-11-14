# **** License ****
# Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
# **** End License ****

from vyatta.platform.detect import DefaultPlatform
from string import Template

class BroadcomNSLPlatform(DefaultPlatform):
    ''' Broadcom Platform class '''

    def _configure_platform(self, conf_file, tmpl_file, tmpl_vars={}):
        ''' Configure the platform based on a template file '''
        with open(tmpl_file, 'r') as t:
            with open(conf_file, 'w') as f:
                template = Template(t.read())
                print(template.substitute(tmpl_vars), file=f)
