check_sophos_xg_*
=================

A collection of monitoring plugins to check [Sophos](https://www.sophos.com/) XG firewalls with [Icinga](https://icinga.com/), [Nagios](https://www.nagios.org/) and other compatible monitoring solutions.

Compatible devices
------------------

- [Sophos](https://www.sophos.com/) XG firewalls 19


Requirements
------------

**General**

- Perl 5
- Perl Modules:
    - Monitoring::Plugin or Nagios::Plugin
    - Net::SNMP
    - Date::Calc (License Check)

**Ubuntu/Debian**

- perl
- libmonitoring-plugin-perl
- libnet-snmp-perl
- libdate-calc-perl


Plugins
-------

### check_sophos_xg_disk.pl

Check disk space.

### check_sophos_xg_ha.pl

Check the HA mode and the current status.

### check_sophos_xg_info.pl

Just some details about the device.

### check_sophos_xg_license.pl

Check if a license has been expired or will expire soon.

### check_sophos_xg_memory.pl

Check memory and swap space.

### check_sophos_xg_service.pl

Check the state of the services running on the device.

### check_sophos_xg_vpn.pl

Check Site-to-Site vpn tunnels and active connections.

Installation
------------

Just copy the files `check_sophos_xg_*.pl` to your Icinga or Nagios plugin directory.

Examples
--------


Source
------

- [Latest source at github.com](https://github.com/DinoTools/monitoring-check_sophos_xg)

Issues
------

Use the [GitHub issue tracker](https://github.com/DinoTools/monitoring-check_sophos_xg/issues) to report any issues

License
-------

GPLv3+
