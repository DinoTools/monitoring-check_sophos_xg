#!/usr/bin/perl
# SPDX-FileCopyrightText: PhiBo from DinoTools (2022)
# SPDX-License-Identifier: GPL-3.0-or-later

use strict;
use warnings FATAL => 'all';

use Pod::Text::Termcap;

use Net::SNMP;

use constant OK       => 0;
use constant WARNING  => 1;
use constant CRITICAL => 2;
use constant UNKNOWN  => 3;

use constant VERSION => '';

my $pkg_monitoring_available = 0;
BEGIN {
    my $pkg_nagios_available = 0;
    eval {
        require Monitoring::Plugin;
        require Monitoring::Plugin::Functions;
        require Monitoring::Plugin::Threshold;
        $pkg_monitoring_available = 1;
    };
    if (!$pkg_monitoring_available) {
        eval {
            require Nagios::Plugin;
            require Nagios::Plugin::Functions;
            require Nagios::Plugin::Threshold;
            *Monitoring::Plugin:: = *Nagios::Plugin::;
            $pkg_nagios_available = 1;
        };
    }
    if (!$pkg_monitoring_available && !$pkg_nagios_available) {
        print("UNKNOWN - Unable to find module Monitoring::Plugin or Nagios::Plugin\n");
        exit UNKNOWN;
    }
}

my @g_long_message;
my $parser = Pod::Text::Termcap->new (sentence => 0, width => 78);
my $extra_doc = <<'END_MESSAGE';
END_MESSAGE

my $extra_doc_output;
$parser->output_string(\$extra_doc_output);
$parser->parse_string_document($extra_doc);

my $mp = Monitoring::Plugin->new(
    shortname => 'Sophos XG Site-to-Site VPN',
    usage => '',
    version => VERSION,
    extra => $extra_doc_output,
);

$mp->add_arg(
    spec    => 'community|C=s',
    help    => 'Community string (Default: public)',
    default => 'public'
);

$mp->add_arg(
    spec => 'hostname|H=s',
    help => 'Hostname or IP of the device with SNMP access enabled',
    required => 1
);

$mp->add_arg(
    spec     => 'username|u=s',
    help     => 'security name',
    # required => 1
);

$mp->add_arg(
    spec     => 'authprotocol|a=s',
    help     => 'Authentication protocol (MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)',
    # required => 1
);

$mp->add_arg(
    spec     => 'authpassphrase|A=s',
    help     => 'Authentication protocol pass phrase',
    # required => 1
);

$mp->add_arg(
    spec     => 'privprotocol|x=s',
    help     => 'Privacy protocol (DES|AES)',
);

$mp->add_arg(
    spec     => 'privpassphrase|X=s',
    help     => 'privacy protocol pass phrase',
);

$mp->add_arg(
    spec    => 'name=s',
    help    => 'Name of the VPN tunnel',
);

$mp->add_arg(
    spec => 'warning=s',
    help => 'Number of vpn connections',
);

$mp->add_arg(
    spec => 'critical=s',
    help => 'Number of vpn connections',
);

$mp->add_arg(
    spec    => 'use-threshold',
    help    => 'Use threshold instead of exect match',
    default => 0,
);

$mp->getopts;

#Open SNMP v3 Session
=begin comment
my ($session, $error) = Net::SNMP->session(
    -hostname => $mp->opts->hostname,
    -version => 'snmpv3',
    -username => $mp->opts->username,
    -authprotocol => $mp->opts->authprotocol,
    -authpassword => $mp->opts->authpassphrase,
    -privprotocol => $mp->opts->privprotocol,
    -privpassword => $mp->opts->privpassphrase,
);
=cut

#Open SNMP v2 Session
my ($session, $error) = Net::SNMP->session(
    -hostname => $mp->opts->hostname,
    -version => 'snmpv2c',
    -community => $mp->opts->community,
);

if (!defined($session)) {
    wrap_exit(UNKNOWN, $error)
}

check();

my ($code, $message) = $mp->check_messages();
wrap_exit($code, $message . "\n" . join("\n", @g_long_message));

sub check
{
    my $sfosIPSecVpnTunnelEntry = '.1.3.6.1.4.1.2604.5.1.6.1.1.1.1';
    my $sfosIPSecVpnConnName     = $sfosIPSecVpnTunnelEntry . '.2';
    my $sfosIPSecVpnActiveTunnel = $sfosIPSecVpnTunnelEntry . '.8';

    my $result = $session->get_table(
        -baseoid => $sfosIPSecVpnTunnelEntry
    );

    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }

    my $vpn_found = 0;
    foreach my $key (keys %$result) {
        if (
            $key =~ /^$sfosIPSecVpnConnName\.(\d+)$/ &&
            $result->{"${sfosIPSecVpnConnName}.${1}"} eq $mp->opts->name
        ) {
            my $vpn_name = $result->{"${sfosIPSecVpnConnName}.${1}"};
            my $vpn_connections = $result->{"${sfosIPSecVpnActiveTunnel}.${1}"};
            $vpn_found = 1;

            my $check_state = OK;
            if ($mp->opts->{'use-threshold'}) {
                my $threshold = Monitoring::Plugin::Threshold->set_thresholds(
                    warning  => $mp->opts->warning,
                    critical => $mp->opts->critical,
                );
                $check_state = $threshold->get_status($vpn_connections);
            } else {
                if ($mp->opts->warning && $mp->opts->warning != $vpn_connections) {
                    $check_state = WARNING;
                }
                if ($mp->opts->critical && $mp->opts->critical != $vpn_connections) {
                    $check_state = CRITICAL;
                }
            }

            $mp->add_perfdata(
                label    => sprintf(
                    '%s_active_connections',
                    $vpn_name,
                ),
                value    => $vpn_connections,
                warning  => $mp->opts->warning,
                critical => $mp->opts->critical,
            );

            my $extra_info = '';
            if ($check_state != OK) {
                $extra_info = sprintf(
                    '(Limit: %s)',
                    ($check_state == WARNING) ? $mp->opts->warning : $mp->opts->critical
                );
            }
            $mp->add_message(
                $check_state,
                sprintf(
                    '%s active connections %d %s',
                    $vpn_name,
                    $vpn_connections,
                    $extra_info,
                )
            );
        }
    }
    if ($vpn_found == 0) {
        wrap_exit(
            UNKNOWN,
            sprintf(
                'Tunnel \'%s\' not found',
                $mp->opts->name,
            )
        );
    }
}

sub wrap_exit
{
    if($pkg_monitoring_available == 1) {
        $mp->plugin_exit( @_ );
    } else {
        $mp->nagios_exit( @_ );
    }
}
