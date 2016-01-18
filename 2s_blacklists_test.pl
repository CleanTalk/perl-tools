#!/usr/bin/perl -w

use strict;
use Encode;
use Data::Dumper;
use utf8;
use JSON::XS;
use LWP::Simple;
use LWP::UserAgent;
use Socket;
use POSIX;
use Getopt::Std;
use File::Slurp;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
$ENV{SSL_VERIFY_NONE} = 0x00;

binmode(STDOUT, 'utf8');

my %opts = (); # Опции командной строки
getopt('idf', \%opts);

my $ip_cli = undef;
if (defined $opts{'i'} && $opts{'i'} =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
    $ip_cli= $opts{'i'};
}

my $log_file = undef;
if (defined $opts{'f'}) {
    $log_file = $opts{'f'};
}

my $logs_dir = undef;
if (defined $opts{'d'}) {
    $logs_dir = $opts{'d'};
}

if (!defined $log_file && !defined $logs_dir) {
    die "Please input a log file (-f) or a directory with log files (-d).\n";
}

# Создаем объект JSON.
my $json_xs = JSON::XS->new->ascii->pretty->allow_nonref;
$json_xs->utf8(1);
 
my $server_endpoint = "https://api.cleantalk.org/";
#$server_endpoint = "http://api.local:81/";
 
# add POST data to HTTP request body
my %post_data = (
    "method_name" => "2s_blacklists_db",
    "auth_key" => "liemouse"
);

my $ua = LWP::UserAgent->new(); 
my $request = $ua->post( $server_endpoint, \%post_data ); 
my $content = $request->decoded_content;

$content = $json_xs->decode($content);
if (defined $$content{'error_message'}) {
    die $$content{'error_message'};
}

my @nets = @{$$content{'data'}};

die 'Empty nets array.' if scalar @nets == 0;

my $ip = undef;
my $ip_dec = undef;
my $bytes = undef;
my $method = undef;
my $return_code = undef;
my $filename = undef;
my %data = ();
my $net_main = undef;
my $mask_main = undef;

if ($ip_cli) {
    $ip_dec = unpack("N",inet_aton(shift||$ip_cli));
    foreach my $rec (@nets) {
        $net_main = $$rec[0];
        $mask_main = $$rec[1];
        if (($ip_dec & $mask_main) == $net_main) {
            printf "Найдено совпадение с записью %s/%s.\n", inet_ntoa($net_main), $mask_main;
        }
    }

    printf "Спам сетей для %s не найдено.\n", $ip_cli;
    exit;

} else {
    my $file = undef;
    my $files = undef;
    my $rows = undef;
    if (defined $logs_dir) {
        if (!opendir(DIR, $logs_dir)) {
            die "Can't read files from $logs_dir: $!"; 
        }
        @{$files} = grep { -f "$logs_dir/$_" } readdir(DIR);
        closedir DIR;
    }
    if (defined $log_file && $log_file =~ /^(.+)\/(.+)$/) {
        $logs_dir = $1;
        push @{$files}, $2;
    }
    foreach (@{$files}) {
        $file = $logs_dir . '/' . $_;
        $rows = read_file($file);
        if ($rows) {
            print "Counting data from $file.\n"
        } else {
            print "Can't read file $file.\n";
            next;
        }
        foreach (split("\n", $rows)) {
            $method = (split)[5];
            next if !defined $method;
            
            $method =~ s/\"//g;
            next if $method ne 'GET';
            
            $filename = (split)[6];
            next if !defined $filename || $filename =~ /[png|gif|jpeg|jpg|ico|bmp|css|js]$/;
            
            $return_code = (split)[8];
            next if !defined $return_code || $return_code !~ /^\d+$/ || $return_code == 304;
            
            $bytes = (split)[9];
            next if !defined $bytes || $bytes !~ /^\d+$/ || $bytes == 0;
            
            $ip = (split)[0];
            next if !defined $ip || $ip !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

            $ip_dec = unpack("N",inet_aton(shift||$ip));
            next if !defined $ip_dec;

            if (defined $data{$ip_dec}{'ip'}) {
                $data{$ip_dec}{'bytes'} = $data{$ip_dec}{'bytes'} + $bytes;
                $data{$ip_dec}{'hits'}++;
            } else {
                $data{$ip_dec}{'bytes'} =  $bytes;
                $data{$ip_dec}{'hits'} = 1;
            }
            $data{$ip_dec}{'ip'} = $ip;
        }
    }
    my $spam_bytes = 0;
    my $spam_hits = 0;
    my $legitimate_bytes = 0;
    my $legitimate_hits = 0;
    my $spam_ips = 0;
    foreach $ip_dec (keys %data) {
        
        $data{$ip_dec}{'spam_bot'} = 0;

        foreach my $rec (@nets) {
            $net_main = $$rec[0];
            $mask_main = $$rec[1];
            $data{$ip_dec}{'spam_bot'} = 1 if ($ip_dec & $mask_main) == $net_main;
        }

        if ($data{$ip_dec}{'spam_bot'} == 1) {
            $spam_bytes = $spam_bytes + $data{$ip_dec}{'bytes'};
            $spam_hits = $spam_hits + $data{$ip_dec}{'hits'};
            $spam_ips++;
        } else {
            $legitimate_bytes = $legitimate_bytes + $data{$ip_dec}{'bytes'};
            $legitimate_hits = $legitimate_hits + $data{$ip_dec}{'hits'};
        }
    }

    my $hits_rate = 0;
    if ($legitimate_hits > 0) {
        $hits_rate = ($spam_hits / $legitimate_hits) * 100;
    }

    my $bytes_rate = 0;
    if ($legitimate_bytes > 0) {
        $bytes_rate = ($spam_bytes / $legitimate_bytes) * 100;
    }

    printf "
    База спам активных адресов/сетей: %d
    IP адресов: %d
    Спам активных IP адресов: %d
    Полезных запросов: %d
    Полезных данных, байт: %d
    Спам запросов: %d
    Спам данных, байт: %d
    Соотношение спам запросов к полезным: %.2f%%
    Соотношение спам данных к полезным: %.2f%%\n",
    scalar @nets,
    scalar keys %data,
    $spam_ips,
    $legitimate_hits,
    $legitimate_bytes,
    $spam_hits,
    $spam_bytes,
    $hits_rate,
    $bytes_rate
    ;
}

if (@ARGV) {
    print Dumper(\@ARGV);
}


