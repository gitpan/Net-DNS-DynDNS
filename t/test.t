#! /usr/bin/perl 

use Net::DNS::DynDNS();
use Test::More(tests => 10);
use strict;
use warnings;

eval { require Net::HTTPS; };
ok($@ eq '', "Loaded Net::HTTPS for secure updates");
my ($default_ip) = Net::DNS::DynDNS->default_ip_address();
ok($default_ip, "Discovered current internet address");
my ($dyn) = new Net::DNS::DynDNS('test', 'test');
ok($dyn, "Created a new Net::DNS::DynDNS object");
my ($assigned_ip);
eval {
	$assigned_ip = Net::DNS::DynDNS->new('test', 'test')->update('test.dyndns.org,test.homeip.net');
};
SKIP: {
	skip("Cannot update test urls:$@", 7) if (($@) && ($@ =~ /^The specified hostname is blocked for update abuse/));
	ok($assigned_ip, "Assigned new IP address to 'test.dyndns.org' and 'test.homeip.net'");
	$assigned_ip = $dyn->update('test.homeip.net', $default_ip, { 'system' => 'dyndns', 'wildcard' => 'ON', 'mx' => 'test.homeip.net', 'backmx' => 'YES', 'offline' => 'NO', 'protocol' => 'http' });
	ok($assigned_ip, "Assigned new IP address to 'test.homeip.net' with every option set, including using the insecure http protocol");
	eval { $dyn->update('test.homeip.net', '10.1.1.1') };
	ok ($@ ne '', "Private IP addresses not allowed\n");
	eval { Net::DNS::DynDNS->new('test', 'wrong_password')->update('test.homeip.net'); };
	ok ($@ =~ /password/i, "Successfully detected that the wrong password has been used");
	$dyn->update_allowed(0); # Fake an error
	eval { $dyn->update('test.homeip.net') };
	ok($@ ne '', "Do not update after a failure from dyndns.org");
	ok(not($dyn->update_allowed(1)), "Signal that human intervention has allowed the object to make update requests again");
	ok($dyn->update('test.homeip.net'), "Successfuly update to dyndns.org");
};
