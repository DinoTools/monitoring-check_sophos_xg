#!/usr/bin/perl
# SPDX-FileCopyrightText: PhiBo from DinoTools (2022)
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
    shortname => "Sophos XG Info",
    usage => "",
    extra => $extra_doc_output
);

$mp->add_arg(
    spec    => 'community|C=s',
    help    => 'Community string (Default: public)',
    default => 'public'
);

$mp->add_arg(
    spec => 'hostname|H=s',
    help => '',
    required => 1
);

$mp->getopts;

#Open SNMP Session
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
    my $sfosDeviceFWVersion = $sfosXGMIBObjects . '.1.3.0';
    my $sfosWebcatVersion = $sfosXGMIBObjects . '.1.5.0';
    my $sfosIPSVersion = $sfosXGMIBObjects . '.1.6.0';

    my $result = $session->get_request(
        -varbindlist => [
            $sfosDeviceFWVersion,
            $sfosWebcatVersion,
            $sfosIPSVersion,
         ]
    );
    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }
    $mp->add_message(OK, 'Firmware: ' . $result->{$sfosDeviceFWVersion});
    $mp->add_message(OK, 'Webcat: ' . $result->{$sfosWebcatVersion});
    $mp->add_message(OK, 'IPS: ' . $result->{$sfosIPSVersion});
}

sub wrap_exit
{
    if($pkg_monitoring_available == 1) {
        $mp->plugin_exit( @_ );
    } else {
        $mp->nagios_exit( @_ );
    }
}
