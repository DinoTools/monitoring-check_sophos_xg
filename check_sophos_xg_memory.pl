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
    shortname => "Sophos XG Disk",
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
    spec => 'memory-warning=s',
    help => 'Allowed values are % of capacity or value in MB (Default: 80% or 20% if --free is set)',
);

$mp->add_arg(
    spec => 'memory-critical=s',
    help => 'Allowed values are % of capacity or value in MB (Default: 90% or 10% if --free is set)',
);

$mp->add_arg(
    spec => 'swap-warning=s',
    help => 'Allowed values are % of capacity or value in MB (Default: 80% or 20% if --free is set)',
);

$mp->add_arg(
    spec => 'swap-critical=s',
    help => 'Allowed values are % of capacity or value in MB (Default: 90% or 10% if --free is set)',
);

$mp->add_arg(
    spec    => 'free',
    help    => 'Check free space instead of used',
    default => 0,
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
    my $sfosMemoryStatus = '.1.3.6.1.4.1.2604.5.1.2.5';
    my $sfosMemoryCapacity     = $sfosMemoryStatus . '.1.0';
    my $sfosMemoryPercentUsage = $sfosMemoryStatus . '.2.0';
    my $sfosSwapCapacity       = $sfosMemoryStatus . '.3.0';
    my $sfosSwapPercentUsage   = $sfosMemoryStatus . '.4.0';

    my $result = $session->get_request(
        -varbindlist => [
            $sfosMemoryCapacity,
            $sfosMemoryPercentUsage,
            $sfosSwapCapacity,
            $sfosSwapPercentUsage,
        ],
    );

    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }

    check_memory(
        'Memory',
        'memory',
        $result->{$sfosMemoryCapacity},
        $result->{$sfosMemoryPercentUsage},
        $mp->opts->{'memory-warning'},
        $mp->opts->{'memory-critical'},
    );
    check_memory(
        'Swap',
        'swap',
        $result->{$sfosSwapCapacity},
        $result->{$sfosSwapPercentUsage},
        $mp->opts->{'swap-warning'},
        $mp->opts->{'swap-critical'},
    );
}

sub check_memory
{
    my ($name, $label_prefix, $capacity, $percent_usage, $opt_warning, $opt_critical) = (@_);

    if ($mp->opts->free) {
        my $percent_free;
        my $percent_free_warning;
        my $percent_free_critical;
        my $capacity_free;
        my $capacity_free_warning;
        my $capacity_free_critical;

        # Set default values
        if (!defined($opt_warning)) {
            $opt_warning = '20%';
        }

        if (!defined($opt_critical)) {
            $opt_critical = '10%';
        }

        $percent_free = 100 - $percent_usage;
        $capacity_free = $capacity * ($percent_free / 100);
        if ($opt_warning =~ /(\d+)%/) {
            $percent_free_warning = $1;
            $capacity_free_warning = $capacity * ($1 / 100);
        } elsif ($opt_warning =~ /(\d+)/) {
            $percent_free_warning = $1 / $capacity * 100;
            $capacity_free_warning = $1;
        }

        if ($opt_critical =~ /(\d+)%/) {
            $percent_free_critical = $1;
            $capacity_free_critical = $capacity * ($1 / 100);
        } elsif ($opt_critical =~ /(\d+)/) {
            $percent_free_critical = $1 / $capacity * 100;
            $capacity_free_critical = $1;
        }

        my $threshold = Monitoring::Plugin::Threshold->set_thresholds(
            warning  => sprintf(
                '%d:',
                $percent_free_warning,
            ),
            critical => sprintf(
                '%d:',
                $percent_free_critical,
            )
        );
        $mp->add_perfdata(
            label    => sprintf(
                '%s_percent_free',
                $label_prefix
            ),
            value    => $percent_free,
            warning  => $percent_free_warning,
            critical => $percent_free_critical,
            uom      => '%',
        );

        $mp->add_perfdata(
            label    => sprintf(
                '%s_capacity_free',
                $label_prefix
            ),
            value    => $capacity_free,
            warning  => $capacity_free_warning,
            critical => $capacity_free_critical,
            min      => 0,
            max      => $capacity,
            uom      => 'MB',
        );

        $mp->add_message(
            $threshold->get_status($percent_free),
            sprintf(
                '%s: %i%% (%iMB) free',
                $name,
                $percent_free,
                $capacity_free,
            )
        );
    } else {
        my $percent_usage_warning;
        my $percent_usage_critical;
        my $capacity_usage;
        my $capacity_usage_warning;
        my $capacity_usage_critical;

        # Set default values
        if (!defined($opt_warning)) {
            $opt_warning = '80%';
        }

        if (!defined($opt_critical)) {
            $opt_critical = '90%';
        }

        $capacity_usage = $capacity * ($percent_usage / 100);
        if ($opt_warning =~ /(\d+)%/) {
            $percent_usage_warning = $1;
            $capacity_usage_warning = $capacity * ($1 / 100);
        } elsif ($opt_warning =~ /(\d+)/) {
            $percent_usage_warning = $1 / $capacity * 100;
            $capacity_usage_warning = $1;
        }

        if ($opt_critical =~ /(\d+)%/) {
            $percent_usage_critical = $1;
            $capacity_usage_critical = $capacity * ($1 / 100);
        } elsif ($opt_critical =~ /(\d+)/) {
            $percent_usage_critical = $1 / $capacity * 100;
            $capacity_usage_critical = $1;
        }

        my $threshold = Monitoring::Plugin::Threshold->set_thresholds(
            warning => $percent_usage_warning,
            critical => $percent_usage_critical
        );
        $mp->add_perfdata(
            label    => sprintf(
                '%s_percent_usage',
                $label_prefix
            ),
            value    => $percent_usage,
            warning  => $percent_usage_warning,
            critical => $percent_usage_critical,
            uom      => '%',
        );

        $mp->add_perfdata(
            label    => sprintf(
                '%s_capacity_usage',
                $label_prefix,
            ),
            value    => $capacity_usage,
            warning  => $capacity_usage_warning,
            critical => $capacity_usage_critical,
            max      => $capacity,
            uom      => 'MB',
        );

        $mp->add_message(
            $threshold->get_status($percent_usage),
            sprintf(
                '%s: %i%% (%iMB) used',
                $name,
                $percent_usage,
                $capacity_usage,
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
