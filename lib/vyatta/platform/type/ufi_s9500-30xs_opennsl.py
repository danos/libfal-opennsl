# **** License ****
# Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
# **** End License ****

from vyatta.platform.detect import PlatformError
from vyatta.platform.broadcomnsl import BroadcomNSLPlatform

def detect(sysmfr='', sysname='', biosver=''):
    if sysmfr != 'Ufi Space' or sysname != 'S9500-30XS':
        raise PlatformError('not identified as this platform')
    return UfiS9500_30XSOpenNSLPlatform()

class UfiS9500_30XSOpenNSLPlatform(BroadcomNSLPlatform):
    """ Representation of the UFI S9500-30XS platform """

    _PLATFORM_TEMPLATE_FILE = "/usr/share/vyatta/platform/s9500/platform.conf.in"

    def is_switch(self):
        """
        Determine if this platform is a switch. If not, then it's a router
        """
        return True

    def get_platform_string(self):
        """
        Get a string that identifies the platform
        """
        return 'ufi.s9500-30xs:opennsl'

    def configure_dataplane(self, conf_file):
        """
        Configure the dataplane for hardware forwarding on the platform
        """
        template_vars = { }
        self._configure_platform(conf_file, self._PLATFORM_TEMPLATE_FILE, template_vars)
