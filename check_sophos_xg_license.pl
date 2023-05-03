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

my @licenses_to_check = ();
my @licenses_available = (
    'base',
    'net-protection',
    'web-protection',
    'web-server-protection',
    'mail-protection',
    'sandstrom',
    'enhanced-support',
    'enhanced-plus-support'
);

my %SubscriptionStatusType = (
    0 => 'none',
    1 => 'evaluating',
    2 => 'notsubscibed',
    3 => 'subscribed',
    4 => 'expired',
    5 => 'deactivated',
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
    shortname => "Sophos XG Licenses",
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
    spec    => 'include=s@',
    help    => sprintf('Included licenses: all, %s (Default: all)', join(', ', @licenses_available)),
    default => []
);

$mp->add_arg(
    spec    => 'exclude=s@',
    help    => sprintf('Excluded licenses: %s (Default: empty list)', join(', ', @licenses_available)),
    default => []
);

$mp->add_arg(
    spec    => 'warning=i',
    help    => 'Warn if less then days left. (Default: 30)',
    default => 30,
);

$mp->add_arg(
    spec    => 'critical=i',
    help    => 'Critical if less then days left. (Default: 15)',
    default => 15,
);

$mp->add_arg(
    spec    => 'status-ok=s@',
    help    => sprintf(
        'Status OK: %s (Default: subscribed)',
        join(', ', values(%SubscriptionStatusType)),
    ),
    default => ['subscribed'],
);

$mp->add_arg(
    spec    => 'verbose',
    help    => 'Print verbose/debug information',
    default => 0,
);

$mp->getopts;

my @licenses_included;
my @status_ok;

if(@{$mp->opts->include} == 0 || grep(/^all$/, @{$mp->opts->include})) {
    @licenses_included = @licenses_available;
} else {
    @licenses_included = @{$mp->opts->include};
}

if(@{$mp->opts->{'status-ok'}} == 0) {
    @status_ok = ['subscribed'];
} else {
    @status_ok = @{$mp->opts->{'status-ok'}};
}

foreach my $name (@licenses_included) {
    if(!grep(/^$name$/, @licenses_available)) {
        wrap_exit(UNKNOWN, sprintf('Unknown license type: %s', $name));
    }

    if(@{$mp->opts->exclude} >0 && grep(/^$name$/, @{$mp->opts->exclude})) {
        next;
    }
    push(@licenses_to_check, $name);
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
    my $sfosXGLicenseDetails = '.1.3.6.1.4.1.2604.5.1.5';
    my $sfosBaseFWLicRegStatus  = $sfosXGLicenseDetails . '.1.1.0';
    my $sfosBaseFWLicExpiryDate = $sfosXGLicenseDetails . '.1.2.0';

    my $sfosNetProtectionLicRegStatus  = $sfosXGLicenseDetails . '.2.1.0';
    my $sfosNetProtectionLicExpiryDate = $sfosXGLicenseDetails . '.2.2.0';

    my $sfosWebProtectionLicRegStatus  = $sfosXGLicenseDetails . '.3.1.0';
    my $sfosWebProtectionLicExpiryDate = $sfosXGLicenseDetails . '.3.2.0';

    my $sfosMailProtectionLicRegStatus  = $sfosXGLicenseDetails . '.4.1.0';
    my $sfosMailProtectionLicExpiryDate = $sfosXGLicenseDetails . '.4.2.0';

    my $sfosWebServerProtectionLicRegStatus  = $sfosXGLicenseDetails . '.5.1.0';
    my $sfosWebServerProtectionLicExpiryDate = $sfosXGLicenseDetails . '.5.2.0';

    my $sfosSandstromLicRegStatus  = $sfosXGLicenseDetails . '.6.1.0';
    my $sfosSandstromLicExpiryDate = $sfosXGLicenseDetails . '.6.2.0';

    my $sfosEnhancedSupportLicRegStatus  = $sfosXGLicenseDetails . '.7.1.0';
    my $sfosEnhancedSupportLicExpiryDate = $sfosXGLicenseDetails . '.7.2.0';

    my $sfosEnhancedPlusLicRegStatus  = $sfosXGLicenseDetails . '.8.1.0';
    my $sfosEnhancedPlusLicExpiryDate = $sfosXGLicenseDetails . '.8.2.0';

    my @oids = ();
    if(grep(/^base$/, @licenses_to_check)) {
        push(@oids, ($sfosBaseFWLicRegStatus, $sfosBaseFWLicExpiryDate));
    }
    if(grep(/^net-protection$/, @licenses_to_check)) {
        push(@oids, ($sfosNetProtectionLicRegStatus, $sfosNetProtectionLicExpiryDate));
    }
    if(grep(/^web-protection$/, @licenses_to_check)) {
        push(@oids, ($sfosWebProtectionLicRegStatus, $sfosWebProtectionLicExpiryDate));
    }
    if(grep(/^mail-protection$/, @licenses_to_check)) {
        push(@oids, ($sfosMailProtectionLicRegStatus, $sfosMailProtectionLicExpiryDate));
    }
    if(grep(/^web-server-protection$/, @licenses_to_check)) {
        push(@oids, ($sfosWebServerProtectionLicRegStatus, $sfosWebServerProtectionLicExpiryDate));
    }
    if(grep(/^sandstrom$/, @licenses_to_check)) {
        push(@oids, ($sfosSandstromLicRegStatus, $sfosSandstromLicExpiryDate));
    }
    if(grep(/^enhanced-support$/, @licenses_to_check)) {
        push(@oids, ($sfosEnhancedSupportLicRegStatus, $sfosEnhancedSupportLicExpiryDate));
    }
    if(grep(/^enhanced-plus-support$/, @licenses_to_check)) {
        push(@oids, ($sfosEnhancedPlusLicRegStatus, $sfosEnhancedPlusLicExpiryDate));
    }

    my $result = $session->get_request(
        -varbindlist => \@oids,
    );

    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }

    if(grep(/^base$/, @licenses_to_check)) {
        check_license(
            'Base',
            $result->{$sfosBaseFWLicRegStatus},
            $result->{$sfosBaseFWLicExpiryDate},
        );
    }
    if(grep(/^net-protection$/, @licenses_to_check)) {
        check_license(
            'Net Protection',
            $result->{$sfosNetProtectionLicRegStatus},
            $result->{$sfosNetProtectionLicExpiryDate},
        );
    }
    if(grep(/^web-protection$/, @licenses_to_check)) {
        check_license(
            'Web Protection',
            $result->{$sfosWebProtectionLicRegStatus},
            $result->{$sfosWebProtectionLicExpiryDate},
        );
    }
    if(grep(/^mail-protection$/, @licenses_to_check)) {
        check_license(
            'Mail Protection',
            $result->{$sfosMailProtectionLicRegStatus},
            $result->{$sfosMailProtectionLicExpiryDate},
        );
    }
    if(grep(/^web-server-protection$/, @licenses_to_check)) {
        check_license(
            'Web-Server Protection',
            $result->{$sfosWebServerProtectionLicRegStatus},
            $result->{$sfosWebServerProtectionLicExpiryDate},
        );
    }
    if(grep(/^sandstrom$/, @licenses_to_check)) {
        check_license(
            'Sandstrom',
            $result->{$sfosSandstromLicRegStatus},
            $result->{$sfosSandstromLicExpiryDate},
        );
    }
    if(grep(/^enhanced-support$/, @licenses_to_check)) {
        check_license(
            'Enhanced Support',
            $result->{$sfosEnhancedSupportLicRegStatus},
            $result->{$sfosEnhancedSupportLicExpiryDate},
        );
    }
    if(grep(/^enhanced-plus-support$/, @licenses_to_check)) {
        check_license(
            'Enhanced Plus Support',
            $result->{$sfosEnhancedPlusLicRegStatus},
            $result->{$sfosEnhancedPlusLicExpiryDate},
        );
    }
}

sub check_license
{
    my $label = shift;
    my $status = shift;
    my $expire_date = shift;
    my $days_left = undef;
    my $expire_state = OK;
    my $status_state = OK;

    if (!grep(/^$SubscriptionStatusType{$status}$/, @{$mp->opts->{'status-ok'}})) {
        $status_state = CRITICAL;
        $mp->add_message($status_state, 'License ' . $label . ' state ' . $SubscriptionStatusType{$status});
    }

    if ($status == 3) {
        $days_left = calc_days_delta($expire_date);
        if (defined($days_left)) {
            $expire_state = WARNING if $days_left < $mp->opts->warning;
            $expire_state = CRITICAL if $days_left < $mp->opts->critical;
            $mp->add_message(
                $expire_state,
                sprintf(
                    'License \'%s\' expires in %d days',
                    $label,
                    $days_left,
                )
            );
        } else {
            $mp->add_message(UNKNOWN, 'Unable to parse expire date of license ' . $label);
        }

    }

    push(
        @g_long_message,
        (
            sprintf(
                'License: %s %s',
                $label,
                ($status_state == OK && $expire_state == OK) ? '' : '!!!'
            ),
            sprintf(
                '- State %s %s',
                $SubscriptionStatusType{$status},
                ($status_state == OK) ? '' : '<--'
            ),
            sprintf(
                '- Expire on %s',
                $expire_date
            )
        )
    );
    if (defined($days_left)) {
        push(
            @g_long_message,
            sprintf(
                '- Expire in %d days %s',
                $days_left,
                ($expire_state == OK) ? '' : '<--'
            )
        );
    }
    push(@g_long_message, '');
}

sub calc_days_delta
{
    my $expire_date = shift;
    my $tm = localtime;
    my %parsed_expire_date = %{parse_expire_date($expire_date)};

    if (!defined($parsed_expire_date{'year'})) {
        return undef;
    }

    return Delta_Days(
        $tm->year() + 1900, $tm->mon() + 1, $tm->mday(),
        $parsed_expire_date{'year'}, $parsed_expire_date{'mon'}, $parsed_expire_date{'mday'}
    );
}

sub parse_expire_date
{
    my $expire_date = shift;
    my %date = (
        year  => undef,
        mon => undef,
        mday  => undef,
    );
    my %month = (
        'Jan' => 1,
        'Feb' => 2,
        'Mar' => 3,
        'Apr' => 4,
        'May' => 5,
        'Jun' => 6,
        'Jul' => 7,
        'Aug' => 8,
        'Sep' => 9,
        'Oct' => 10,
        'Nov' => 11,
        'Dec' => 12,
    );
    if ($expire_date =~ /([A-Z][a-z][a-z])\s+(\d+)\s+(\d+)/) {
        $date{'year'} = $3;
        $date{'mon'} = $month{$1};
        $date{'mday'} = $2;
    }
    return \%date;
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
