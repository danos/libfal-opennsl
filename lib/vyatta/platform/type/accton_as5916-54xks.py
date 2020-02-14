# **** License ****
# Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
# **** End License ****

from vyatta.platform.detect import PlatformError
from vyatta.platform.broadcomnsl import BroadcomNSLPlatform
import vyatta.platform.accton_as5916_54xks_sfphelper

def detect(sysmfr='', sysname='', biosver=''):
    if sysmfr != 'Accton' or sysname != 'AS5916-54XKS':
        raise PlatformError('not identified as this platform')
    return AcctonAS5916_54XKSPlatform()

class AcctonAS5916_54XKSPlatform(BroadcomNSLPlatform):
    """ Representation of the Accton AS5916-54XKS platform """

    _PLATFORM_TEMPLATE_FILE = "/usr/share/vyatta/platform/as5916-54xks/platform.conf.in"

    def is_switch(self):
        """
        Determine if this platform is a switch. If not, then it's a router
        """
        return True

    def get_platform_string(self):
        """
        Get a string that identifies the platform
        """
        return 'accton.as5916-54xks:opennsl'

    def get_sfp_helper_module(self):
        """
        Get the platform-depdendent module that allows SFP state to be
        managed.
        """
        return vyatta.platform.accton_as5916_54xks_sfphelper

    def configure_dataplane(self, conf_file):
        """
        Configure the dataplane for hardware forwarding on the platform
        """
        template_vars = { 'mac_lines': '' }

        self._configure_platform(conf_file, self._PLATFORM_TEMPLATE_FILE, template_vars)
