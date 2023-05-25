#!/usr/bin/perl
# SPDX-FileCopyrightText: PhiBo from DinoTools (2023)
# SPDX-License-Identifier: GPL-3.0-or-later

use strict;
use warnings FATAL => 'all';

use Pod::Text::Termcap;

use Net::SNMP;

use constant OK         => 0;
use constant WARNING    => 1;
use constant CRITICAL   => 2;
use constant UNKNOWN    => 3;

my $sfosXGMIBObjects = '.1.3.6.1.4.1.2604.5.1';
my $sfosXGHAStats    = $sfosXGMIBObjects . '.4';

my $pkg_monitoring_available = 0;
BEGIN {
    my $pkg_nagios_available = 0;
    eval {
        require Monitoring::Plugin;
        require Monitoring::Plugin::Functions;
        $pkg_monitoring_available = 1;
    };
    if (!$pkg_monitoring_available) {
        eval {
            require Nagios::Plugin;
            require Nagios::Plugin::Functions;
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
    shortname => "Sophos XG HA",
    usage => "",
    extra => $extra_doc_output
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
    spec    => 'verbose',
    help    => 'Print verbose/debug information',
    default => 0,
);

$mp->add_arg(
    spec    => 'disabled-ok',
    help    => 'If the HA status is disabled, the check will return OK instead of a WARNING and not perform any other checks',
    default => 0,
);

$mp->add_arg(
    spec    => 'expected-mode=s@',
    help    => 'Check if the HA mode is as expected. Example: Active-Passive',
    default => [],
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
    my $sfosHAStatus             = $sfosXGHAStats . '.1.0';
    my $sfosDeviceCurrentHAState = $sfosXGHAStats . '.4.0';
    my $sfosDevicePeerHAState    = $sfosXGHAStats . '.5.0';
    my $sfosDeviceHAConfigMode   = $sfosXGHAStats . '.6.0';
    my $sfosDeviceLoadBalancing  = $sfosXGHAStats . '.7.0';

    my %HaStatusType = (
        0 => 'disabled',
        1 => 'enabled',
    );

    my %HaState = (
        0 => 'notapplicable',
        1 => 'auxiliary',
        2 => 'standalone',
        3 => 'primary',
        4 => 'faulty',
        5 => 'ready',
    );

    my %LoadBalancingType = (
        0 => 'notapplicable',
        1 => 'loadBalanceOff',
        2 => 'loadBalanceOn',
    );

    my $result = $session->get_request(
        -varbindlist => [
            $sfosHAStatus,
            $sfosDeviceCurrentHAState,
            $sfosDevicePeerHAState,
            $sfosDeviceHAConfigMode,
            $sfosDeviceLoadBalancing,
         ]
    );
    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }

    if ($result->{$sfosHAStatus} != 1) {
        my $state = WARNING;
        my $message = 'HA is disabled but it should be enabled';
        if ($mp->opts->{'disabled-ok'}) {
            # Exit with OK if a disabled HA mode is OK
            $state = OK;
            $message = 'HA mode is disabled and this is okay.';
        }
        wrap_exit($state, $message);
    }

    $mp->add_message(OK, 'HA enabled');
    my $message = sprintf(
        'HA State device: %s peer: %s',
        $HaState{$result->{$sfosDeviceCurrentHAState}},
        $HaState{$result->{$sfosDevicePeerHAState}}
    );

    if ($result->{$sfosDeviceCurrentHAState} == 3 or $result->{$sfosDevicePeerHAState}) {
        $mp->add_message(OK, $message);
    } else {
        $mp->add_message(CRITICAL, 'No primary peer found: ' . $message);
    }

    if(@{$mp->opts->{'expected-mode'}} > 0) {
        if (!grep(/^$result->{$sfosDeviceHAConfigMode}$/, @{$mp->opts->{'expected-mode'}})) {
            $mp->add_message(
                WARNING,
                sprintf(
                    'Mode is "%s" but expected "%s"',
                    $result->{$sfosDeviceHAConfigMode},
                    join(', ', @{$mp->opts->{'expected-mode'}})
                )
            );
        }
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
