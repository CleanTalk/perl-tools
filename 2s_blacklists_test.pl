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

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
$ENV{SSL_VERIFY_NONE} = 0x00;

# Создаем объект JSON.
my $json_xs = JSON::XS->new->ascii->pretty->allow_nonref;
$json_xs->utf8(1);
 
my $server_endpoint = "https://api.cleantalk.org/";
#$server_endpoint = "http://api.local:81/";
 
# add POST data to HTTP request body
my %post_data = (
    "method_name" => "2s_blacklists_db",
    "auth_key" => "bu5asysyje4a"
);

my $ua = LWP::UserAgent->new(); 
my $request = $ua->post( $server_endpoint, \%post_data ); 
my $content = $request->decoded_content;

$content = $json_xs->decode($content);
my @nets = @{$$content{'data'}};

die 'Empty nets array.' if scalar @nets == 0;

my $ip = undef;
my $ip_dec = undef;
my $bytes = undef;
my $method = undef;
my $return_code = undef;
my $filename = undef;
my %data = ();

while (<>) {
    $method = (split)[5];
    $method =~ s/\"//g;
    next if !defined $method || $method ne 'GET';
    
    $filename = (split)[6];
    next if !defined $filename || $filename =~ /[png|gif|jpeg|jpg|ico|bmp|css|js]$/;
    
    $return_code = (split)[8];
    next if !defined $return_code || $return_code !~ /^\d+$/ || $return_code == 304;
    
    $bytes = (split)[9];
    next if !defined $bytes || $bytes !~ /^\d+$/ || $bytes == 0;
    
    $ip = (split)[0];
    next if !defined $ip;
    
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

my $net_main = undef;
my $mask_main = undef;
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

#print Dumper(\%data);

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
($spam_hits / $legitimate_hits) * 100,
($spam_bytes / $legitimate_bytes) * 100
;

