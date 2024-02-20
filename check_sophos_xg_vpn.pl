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

my %IPSecVPNConnectionStatus = (
    0 => 'inactive',
    1 => 'active',
    2 => 'partially-active',
);

my %IPSecVPNActivationStatus = (
    0 => 'inactive',
    1 => 'active',
);

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
=pod

=head1 Requirements

The required information where introduced in Sophos XG v20.0

=head1 Connection state

This check plugin uses the information from the documentation [0] to report the
status of the Site-to-Site VPN connection.

[0] https://doc.sophos.com/nsg/sophos-firewall/20.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/SiteToSiteVPN/IPsec/index.html#connection-status
=cut
END_MESSAGE

my $extra_doc_output;
$parser->output_string(\$extra_doc_output);
$parser->parse_string_document($extra_doc);

my $mp = Monitoring::Plugin->new(
    shortname => 'Sophos XG Site-to-Site VPN',
    usage => 'This check plugin checks the current the of a Site-to-Site VPN connection',
    version => VERSION,
    extra => $extra_doc_output,
);

$mp->add_arg(
    spec    => 'community|C=s',
    help    => 'Community string (Default: public)',
    default => 'public'
);

$mp->add_arg(
    spec     => 'hostname|H=s',
    help     => 'Hostname or IP of the device with SNMP access enabled',
    required => 1
);

$mp->add_arg(
    spec => 'username|u=s',
    help => 'Username for SNMPv3',
);

$mp->add_arg(
    spec => 'authpassword|A=s',
    help => 'Authentication protocol password',
);

$mp->add_arg(
    spec    => 'authprotocol|a=s',
    help    => 'Authentication protocol: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512 (Default: MD5)',
    default => 'md5',
);

$mp->add_arg(
    spec => 'privpassword|X=s',
    help => 'privacy protocol password',
);

$mp->add_arg(
    spec    => 'privprotocol|x=s',
    help    => 'Privacy protocol: DES, AES (Default: DES)',
    default => 'des',
);

$mp->add_arg(
    spec    => 'name=s@',
    help    => 'Name of the VPN tunnel',
);

$mp->add_arg(
    spec    => 'inactive-ok',
    help    => 'If it is OK if the activation state of the IPSec tunnel is inactive.',
    default => 0,
);

$mp->add_arg(
    spec    => 'ha',
    help    => 'Check connections in HA mode.',
    default => 0,
);

$mp->add_arg(
    spec    => 'verbose',
    help    => 'Print verbose/debug information',
    default => 0,
);

$mp->getopts;

my ($session, $error);
if (defined($mp->opts->username) && defined($mp->opts->authpassword)) {
    # SNMPv3 login
    verb('SNMPv3 login');
    if (!defined($mp->opts->privpassword)) {
        verb('SNMPv3 AuthNoPriv login : %s, %s', $mp->opts->username, $mp->opts->authprotocol);
        ($session, $error) = Net::SNMP->session(
            -hostname => $mp->opts->hostname,
            -version => 'snmpv3',
            -username => $mp->opts->username,
            -authprotocol => $mp->opts->authprotocol,
            -authpassword => $mp->opts->authpassword,
        );
    } else {
        verb('SNMPv3 AuthPriv login : %s, %s, %s', $mp->opts->username, $mp->opts->authprotocol, $mp->opts->privprotocol);
        ($session, $error) = Net::SNMP->session(
            -hostname => $mp->opts->hostname,
            -version => 'snmpv3',
            -username => $mp->opts->username,
            -authprotocol => $mp->opts->authprotocol,
            -authpassword => $mp->opts->authpassword,
            -privprotocol => $mp->opts->privprotocol,
            -privpassword => $mp->opts->privpassword,
        );
    }
} else {
  verb('SNMP v2c login');
  ($session, $error) = Net::SNMP->session(
      -hostname => $mp->opts->hostname,
      -version => 'snmpv2c',
      -community => $mp->opts->community,
  );
}

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
    my $sfosIPSecVpnConnStatus   = $sfosIPSecVpnTunnelEntry . '.9';
    my $sfosIPSecVpnActivated    = $sfosIPSecVpnTunnelEntry . '.10';

    my $result = $session->get_table(
        -baseoid => $sfosIPSecVpnTunnelEntry
    );

    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }

    my %vpn_connections = ();
    foreach my $key (keys %$result) {
        if ($key =~ /^$sfosIPSecVpnConnName\.(\d+)$/) {
            my $vpn_connection_id = $1;
            my $vpn_name = $result->{"${sfosIPSecVpnConnName}.${vpn_connection_id}"};
            $vpn_connections{$vpn_name} = {
                name => $vpn_name,
                activated => $result->{"${sfosIPSecVpnActivated}.${vpn_connection_id}"},
                status => $result->{"${sfosIPSecVpnConnStatus}.${vpn_connection_id}"}
            };
        }
    }

    my $vpn_connection_ha_activate = undef;

    foreach my $name (@{$mp->opts->name}) {
        my $vpn_found = 0;
        foreach my $vpn_name (keys %vpn_connections) {
            if ($name ne $vpn_name) {
                next;
            }
            $vpn_found = 1;
            my $vpn_connection = $vpn_connections{$vpn_name};
            if ($mp->opts->ha) {
                if ($vpn_connection->{activated} == 1) {
                    if(defined $vpn_connection_ha_activate) {
                        wrap_exit(
                            UNKNOWN,
                            sprintf(
                                'Only one active connection is allowed in HA mode. Active connections: \'%s\' and \'%s\'',
                                $vpn_connection_ha_activate->{name},
                                $name,
                            )
                        );
                    }
                    $vpn_connection_ha_activate = $vpn_connection;
                }
            } else {
                check_single_connection($vpn_connection);
            }
        }
        if ($vpn_found == 0) {
            wrap_exit(
                UNKNOWN,
                sprintf(
                    'Connection \'%s\' not found',
                    $name,
                )
            );
        }
    }
    if ($mp->opts->ha) {
        if(defined $vpn_connection_ha_activate) {
            check_single_connection($vpn_connection_ha_activate);
        } else {
            $mp->add_message(
                CRITICAL,
                'No active connection in HA group found.'
            );
        }
    }
}

sub check_single_connection
{
    my $vpn_connection = shift;
    if ($vpn_connection->{activated} == 1) {
        if ($vpn_connection->{status} == 0) {
            $mp->add_message(
                CRITICAL,
                sprintf(
                    'Connection \'%s\' is active, but tunnel isn\'t established.',
                    $vpn_connection->{name},
                )
            );
        } elsif ($vpn_connection->{status} == 1) {
            $mp->add_message(
                OK,
                sprintf(
                    'Connection \'%s\' is active and tunnels are established.',
                    $vpn_connection->{name},
                )
            );
        } elsif ($vpn_connection->{status} == 2) {
            $mp->add_message(
                WARNING,
                sprintf(
                    'Connection \'%s\' is active, but at least one tunnel isn\'t established.',
                    $vpn_connection->{name},
                )
            );
        } else {
            $mp->add_message(
                UNKNOWN,
                sprintf(
                    'Connection \'%s\' is active, but an unknown status code has been reported by the devices.',
                    $vpn_connection->{name},
                )
            );

        }

    } elsif ($mp->opts->{'inactive-ok'}) {
        $mp->add_message(
            OK,
            sprintf(
                'Connection \'%s\' is not active, but this is ok.',
                $vpn_connection->{name},
            )
        );
    } else {
        $mp->add_message(
            CRITICAL,
            sprintf(
                'Connection \'%s\' is not active',
                $vpn_connection->{name},
            )
        );
    }
}

sub verb
{
    my $t = shift;
    if ($mp->opts->verbose) {
      printf($t . "\n", @_);
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
