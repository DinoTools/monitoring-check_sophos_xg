#!/usr/bin/perl
# SPDX-FileCopyrightText: PhiBo from DinoTools (2022)
# SPDX-License-Identifier: GPL-3.0-or-later

use strict;
use warnings FATAL => 'all';

use Pod::Text::Termcap;

use Time::localtime;
use Date::Calc qw(Delta_Days);
use Net::SNMP;

use constant OK       => 0;
use constant WARNING  => 1;
use constant CRITICAL => 2;
use constant UNKNOWN  => 3;

use constant VERSION => '';

my $sfosXGServiceStatus = '.1.3.6.1.4.1.2604.5.1.3';
my %services = (
    pop3 => {
        oid   => $sfosXGServiceStatus . '.1.0',
        label => 'POP3',
    },
    imap4 => {
        oid => $sfosXGServiceStatus . '.2.0',
        label => 'IMAP4',
    },
    smtp => {
        oid => $sfosXGServiceStatus . '.3.0',
        label => 'SMTP',
    },
    ftp => {
        oid => $sfosXGServiceStatus . '.4.0',
        label => 'FTP',
    },
    http => {
        oid => $sfosXGServiceStatus . '.5.0',
        label => 'HTTP',
    },
    av => {
        oid => $sfosXGServiceStatus . '.6.0',
        label => 'AV',
    },
    as => {
        oid => $sfosXGServiceStatus . '.7.0',
        label => 'AS',
    },
    dns => {
        oid => $sfosXGServiceStatus . '.8.0',
        label => 'DNS',
    },
    ha => {
        oid => $sfosXGServiceStatus . '.9.0',
        label => 'HA',
    },
    ips => {
        oid => $sfosXGServiceStatus . '.10.0',
        label => '',
    },
    apache => {
        oid => $sfosXGServiceStatus . '.11.0',
        label => 'Apache',
    },
    ntp => {
        oid => $sfosXGServiceStatus . '.12.0',
        label => 'NTP',
    },
    tomcat => {
        oid => $sfosXGServiceStatus . '.13.0',
        label => 'Tomcat',
    },
    'vpn-ssl' => {
        oid => $sfosXGServiceStatus . '.14.0',
        label => 'SSL-VPN',
    },
    'vpn-ipsec' => {
        oid => $sfosXGServiceStatus . '.15.0',
        label => 'IPSec VPN',
    },
    database => {
        oid => $sfosXGServiceStatus . '.16.0',
        label => 'Database',
    },
    network => {
        oid => $sfosXGServiceStatus . '.17.0',
        label => 'Network',
    },
    garner => {
        oid => $sfosXGServiceStatus . '.18.0',
        label => 'Garner',
    },
    drouting => {
        oid => $sfosXGServiceStatus . '.19.0',
        label => 'Drouting',
    },
    sshd => {
        oid => $sfosXGServiceStatus . '.20.0',
        label => 'SSHd',
    },
    dgd => {
        oid => $sfosXGServiceStatus . '.21.0',
        label => 'Device and Group Discovery',
    }
);
my @services_to_check = ();
my @services_available = keys %services;

my %ServiceStatusType = (
    0 => 'untouched',
    1 => 'stopped',
    2 => 'initializing',
    3 => 'running',
    4 => 'exiting',
    5 => 'dead',
    6 => 'frozen',
    7 => 'unregistered',
);

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
    shortname => "Sophos XG services",
    usage     => '',
    version   => VERSION,
    extra     => $extra_doc_output,
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
    spec    => 'include=s@',
    help    => sprintf(
        'Include the given services in the check.'
        . ' This option can be specified multiple times'
        . ' Allowed values are: all, %s (Default: all)',
        join(', ', @services_available)
    ),
    default => []
);

$mp->add_arg(
    spec    => 'exclude=s@',
    help    => sprintf(
        'Exclud the given services from the check.'
        . ' This option can be specified multiple times'
        . ' Allowed values are: %s (Default: empty list)',
        join(', ', @services_available)
    ),
    default => []
);

$mp->add_arg(
    spec    => 'status-warning=s@',
    help    => sprintf(
        'Report warning if a service is in this state.'
        . ' This option can be specified multiple times.'
        . ' Allowed values: %s (Default: [])',
        join(', ', values(%ServiceStatusType)),
    ),
    default => [],
);

$mp->add_arg(
    spec    => 'status-ok=s@',
    help    => sprintf(
        'If a service is in the specified state it is OK.'
        . ' If not it is critical.'
        . ' This option can be specified multiple times.'
        . ' Allowed values: %s (Default: running)',
        join(', ', values(%ServiceStatusType)),
    ),
    default => ['running'],
);

$mp->add_arg(
    spec    => 'verbose',
    help    => 'Print verbose/debug information',
    default => 0,
);

$mp->getopts;

my @services_included;
my @status_ok;
my @status_warning;

if(@{$mp->opts->include} == 0 || grep(/^all$/, @{$mp->opts->include})) {
    @services_included = @services_available;
} else {
    @services_included = @{$mp->opts->include};
}

if(@{$mp->opts->{'status-ok'}} == 0) {
    @status_ok = ['running'];
} else {
    @status_ok = @{$mp->opts->{'status-ok'}};
}

@status_warning = @{$mp->opts->{'status-warning'}};

foreach my $name (@services_included) {
    if(!grep(/^$name$/, @services_available)) {
        wrap_exit(UNKNOWN, sprintf('Unknown service type: %s', $name));
    }

    if(@{$mp->opts->exclude} >0 && grep(/^$name$/, @{$mp->opts->exclude})) {
        next;
    }
    push(@services_to_check, $name);
}

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
        verb('SNMPv3 AuthPriv login : %s, %s, %s', ${mp->opts->username}, ${mp->opts->authprotocol}, ${mp->opts->privprotocol});
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
    my @oids = ();
    foreach my $key (keys %services) {
        if(grep(/^${key}$/, @services_to_check)) {
            push(@oids, $services{$key}{'oid'});
        }
    }

    my $result = $session->get_request(
        -varbindlist => \@oids,
    );

    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }

    foreach my $key (sort keys %services) {
        my $status = $result->{$services{$key}{'oid'}};
        my $label = $services{$key}{'label'};
        if(grep(/^${key}$/, @services_to_check)) {
            my $status_state = OK;
            if (grep(/^$ServiceStatusType{$status}$/, @status_warning)) {
                $status_state = WARNING;
                $mp->add_message($status_state, 'Service ' . $label . ' state ' . $ServiceStatusType{$status});
            } elsif (!grep(/^$ServiceStatusType{$status}$/, @status_ok)) {
                $status_state = CRITICAL;
                $mp->add_message($status_state, 'Service ' . $label . ' state ' . $ServiceStatusType{$status});
            }

            push(
                @g_long_message,
                'Services:',
            );
            push(
                @g_long_message,
                (
                    sprintf(
                        '- %s: %s %s',
                        $label,
                        $ServiceStatusType{$status},
                        ($status_state == OK) ? '' : '!!!'
                    ),
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
