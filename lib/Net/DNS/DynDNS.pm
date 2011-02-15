package Net::DNS::DynDNS;

use LWP();
use HTTP::Cookies();
use HTTP::Headers();
use warnings;
use strict;
our ($VERSION) = '0.96';

sub new {
	my ($class, $user_name, $password, $params) = @_;
	my ($self) = {};
	my ($timeout) = 60;
	if ((ref $user_name) && (ref $user_name eq 'SCALAR')) {
		unless ((ref $password) && (ref $password eq 'SCALAR')) {
			die("No password supplied\n");
		}
	} elsif ((ref $user_name) && ((ref $user_name) eq 'HASH')) {
		$params = $user_name;
		$user_name = undef;
		$password = undef;
	}
	if (exists $params->{timeout}) {
		if (($params->{timeout}) && ($params->{timeout} =~ /^\d+$/)) {
			$timeout = $params->{timeout};
		} else {
			die("The 'timeout' parameter must be a number\n");
		}
	}
	my ($name) = "Net::DNS::DynDNS $VERSION "; # a space causes the default LWP User Agent to be appended.
	if (exists $params->{user_agent}) {
		if (($params->{user_agent}) && ($params->{user_agent} =~ /\S/)) {
			$name = $params->{user_agent};
		}
	}
	my ($ua) = new LWP::UserAgent( timeout => $timeout ); # no sense in using keep_alive => 1 because updates and checks are supposed to happen infrequently
	$ua->agent($name);
	my ($cookieJar) = new HTTP::Cookies( hide_cookie2 => 1 );
	$ua->cookie_jar($cookieJar);
	$ua->requests_redirectable([ 'GET' ]);
	$self->{_ua} = $ua;
	my ($headers) = new HTTP::Headers();
	if (($user_name) && ($password)) {
		$headers->authorization_basic($user_name, $password);
	}
	$self->{_headers} = $headers;
	$self->{server} = $params->{server} || 'dyndns.org';
	$self->{dns_server} = $params->{dns_server} || 'members.dyndns.org';
	$self->{check_ip} = $params->{check_ip} || 'checkip.dyndns.org';
	bless $self, $class;
	$self->update_allowed(1);
	return ($self);
}

sub _get {
	my ($self, $url) = @_;
	my ($ua) = $self->{_ua};
	my ($headers) = $self->{_headers};
	my ($request) = new HTTP::Request('GET' => $url, $headers);
	my ($response);
	eval {
		local $SIG{'ALRM'} = sub { die("Timeout\n"); };
		alarm $ua->timeout();
		$response = $ua->request($request);
		alarm 0;
	};
	if ($@) {
		die("Failed to get a response from '$url':$@\n");
	}
	return ($response);
}

sub default_ip_address {
	my ($proto, $params) = @_;
	my ($self);
	if (ref $proto) {
		$self = $proto;
	} else {
		$self = $proto->new($params);
	}
	my ($protocol) = 'http'; # default protocol is http because no user_name / passwords are required
	if (exists $params->{protocol}) {
		if ((defined $params->{protocol}) && ($params->{protocol})) {
			$params->{protocol} = lc($params->{protocol});
			unless (($params->{protocol} eq 'http') || 
				($params->{protocol} eq 'https'))
			{
				die("The 'protocol' parameter must be one of 'http' or 'https'\n");	
			}
		} else {
			die("The 'protocol' parameter must be one of 'http' or 'https'\n");	
		}
		$protocol = $params->{protocol};
	}
	if ($protocol eq 'https') {
		eval { require Net::HTTPS; };
		if ($@) {
			die("Cannot load Net::HTTPS\n");
		}
	}
	my ($check_ip_url) = $protocol . '://' . $self->{check_ip};

	# user_name / password is not necessary for checkip.
	# therefore don't send user_name / password

	my ($headers) = $self->{_headers};
	my ($user_name, $password) = $headers->authorization_basic();
	$headers->remove_header('Authorization');
	
	my ($response);
	eval {
		$response = $self->_get($check_ip_url);
	};
	my ($network_error);
	if ($@) {
		$network_error = $@;
	}
		
	# restore user_name / password

	if (($user_name) && ($password)) {
		$headers->authorization_basic($user_name, $password);
	}

	if ($network_error) {
		die($network_error);
	}

	my ($ip_address);
	if ($response->is_success()) {
		my ($content) = $response->content();	
		if ($content =~ /Current IP Address: (\d+.\d+.\d+.\d+)/) {
			$ip_address = $1;
		} else {
			die("Failed to parse response from '$check_ip_url'\n$content\n");
		}
	} else {
		my ($content) = $response->content();
		if ($content =~ /Can't connect to $self->{check_ip}/) {
			die("Failed to connect to '$check_ip_url'\n");
		} else {
			die("Failed to get a success type response from '$check_ip_url'\n");
		}
	}
	return ($ip_address);
}

sub _validate_update {
	my ($self, $hostnames, $ip_address, $params) = @_;
	my ($headers) = $self->{_headers};
	my ($user_name, $password) = $headers->authorization_basic();
	unless ($self->update_allowed()) {
		die("$self->{server} has forbidden updates until the previous error is corrected\n");	
	}
	unless (($user_name) && ($password)) {
		die("Username and password must be supplied for an update\n");
	}
	unless ($hostnames) {
		die("The update method must be supplied with a hostname\n");
	}
	unless ($hostnames =~ /^(?:(?:[\w\-]+\.)+[\w\-]+,?)+$/) {
		die("The hostnames do not seem to be in a valid format.  Try 'test.$self->{server}'\n");
	}
	if (defined $ip_address) {
		my (@bytes) = split(/\./, $ip_address);
		unless ((scalar @bytes) == 4) {
			die("Bad IP address\n");
		}
		my ($byte);
		foreach $byte (@bytes) {
			unless ($byte =~ /^\d+/) {
				die("Bad IP address.  Each byte must be numeric\n");
			}
			unless (($byte < 256) && ($byte >= 0)) {
				die("Bad IP address.  Each byte must be within 0-255\n");
			}
		}
		if (($bytes[0] == 0) || # default route
				($bytes[0] == 127) || # localhost
				($bytes[0] == 10) || # private
				(($bytes[0] == 172) && ($bytes[1] == 16)) || # private
				(($bytes[0] == 172) && ($bytes[1] == 16)) || # private
				(($bytes[0] == 192) && ($bytes[1] == 168)) || # private
				($bytes[0] >= 224)) # multicast && reserved
		{
			die("Bad IP address.  The IP address is in a range that is not suitable for the $self->{server} system\n");
		}
	}
	if ((ref $params) && ((ref $params) eq 'HASH')) {
		if (exists $params->{system}) {
			if ((defined $params->{system}) && ($params->{system})) {
				$params->{system} = lc($params->{system});
				unless (($params->{system} eq 'dyndns') || 
					($params->{system} eq 'statdns') || 
					($params->{system} eq 'custom'))
				{
					die("The 'system' parameter must be one of 'dyndns','statdns' or 'custom'\n");	
				}
			} else {
				die("The 'system' parameter must be one of 'dyndns','statdns' or 'custom'\n");	
			}
		}
		if (exists $params->{wildcard}) {
			if ((defined $params->{wildcard}) && ($params->{wildcard})) {
				unless (($params->{system} eq 'dyndns') || ($params->{system} eq 'statdns')) {
					die("Not allowed to set 'wildcard' parameter unless the 'system' parameter is 'dyndns' or 'statdns'\n");
				}
				$params->{wildcard} = uc($params->{wildcard});
				unless (($params->{wildcard} eq 'ON') || 
					($params->{wildcard} eq 'OFF') || 
					($params->{wildcard} eq 'NOCHG'))
				{
					die("The 'wildcard' parameter must be one of 'ON','OFF' or 'NOCHG'\n");	
				}
			} else {
				die("The 'wildcard' parameter must be one of 'ON','OFF' or 'NOCHG'\n");	
			}
		}
		if (exists $params->{mx}) {
			if ((defined $params->{mx}) && ($params->{mx})) {
				unless (($params->{system} eq 'dyndns') || ($params->{system} eq 'statdns')) {
					die("Not allowed to set 'mx' parameter unless the 'system' parameter is 'dyndns' or 'statdns'\n");
				}
				unless ($params->{mx} =~ /^(?:(?:\w+\.)+\w+,?)+$/) {
					die("The 'mx' parameter does not seem to be in a valid format.  Try 'test.$self->{server}'\n");
				}
			} else {
				die("The 'mx' parameter must be a valid fully qualified domain name\n");
			}
		} else {
			if (exists $params->{backmx}) {
				die("The 'backmx' parameter cannot be set without specifying the 'mx' parameter\n");
			}
		}
		if (exists $params->{backmx}) {
			if ((defined $params->{backmx}) && ($params->{backmx})) {
				$params->{backmx} = uc($params->{backmx});
				unless (($params->{backmx} eq 'YES') || 
					($params->{backmx} eq 'NO'))
				{
					die("The 'backmx' parameter must be one of 'YES' or 'NO'\n");	
				}
			} else {
				die("The 'backmx' parameter must be one of 'YES' or 'NO'\n");	
			}
		}
		if (exists $params->{offline}) {
			if ((defined $params->{offline}) && ($params->{offline})) {
				$params->{offline} = uc($params->{offline});
				unless (($params->{offline} eq 'YES') || 
					($params->{offline} eq 'NO'))
				{
					die("The 'offline' parameter must be one of 'YES' or 'NO'\n");	
				}
			} else {
				die("The 'offline' parameter must be one of 'YES' or 'NO'\n");	
			}
		}
		if (exists $params->{protocol}) {
			if ((defined $params->{protocol}) && ($params->{protocol})) {
				$params->{protocol} = lc($params->{protocol});
				unless (($params->{protocol} eq 'http') || 
					($params->{protocol} eq 'https'))
				{
					die("The 'protocol' parameter must be one of 'http' or 'https'\n");	
				}
			} else {
				die("The 'protocol' parameter must be one of 'http' or 'https'\n");	
			}
		} else {
			$params->{protocol} = 'https';
		}
	} elsif ($params) {
		die("Extra parameters must be passed in as a reference to a hash\n");
	}
}

sub update_allowed {
	my ($self, $allowed) = @_;
	my ($old);
	if ((exists $self->{update_allowed}) && ($self->{update_allowed})) {
		$old = $self->{update_allowed};	
	}
	if (defined $allowed) {
		$self->{update_allowed} = $allowed;
	}
	return ($old);
}

sub _error {
	my ($self, $code, $content) = @_;
	$self->update_allowed(0);
	if ($code eq 'badsys') {
		$self->{error} = "The 'system' parameter must be one of 'dyndns','statdns' or 'custom'";
	} elsif ($code eq 'badagent') {
		$self->{error} = "This user-agent has been blocked for not following the specification";
	} elsif ($code eq 'badauth') {
		$self->{error} = "The username/password specified are incorrect";
	} elsif ($code eq '!donator') {
		$self->{error} = "This option is only available to credited users";
	} elsif ($code eq 'notfqdn') {
		$self->{error} = "The specified hostname is not a fully qualified domain name";
	} elsif ($code eq 'nohost') {
		$self->{error} = "The specified hostname does not exist";
	} elsif ($code eq '!yours') {
		$self->{error} = "The specified hostname exists, but not under the username specified";
	} elsif ($code eq 'abuse') {
		$self->{error} = "The specified hostname is blocked for update abuse";
	} elsif ($code eq 'numhost') {
		$self->{error} = "Too many or too few hosts found";
	} elsif ($code eq 'dnserr') {
		$self->{error} = "Remote DNS error encountered";
	} elsif ($code eq '911') {
		$self->{error} = "Serious problem at $self->{server}. Check http://www.$self->{server}/news/status/";
	} else {
		$self->{error} = "Unknown error:$code";
	}
	die("$self->{error}\n$content\n");
}

sub update {
	my ($self, $hostnames, $ip_address, $params) = @_;
	if ((ref $ip_address) && (ref $ip_address eq 'HASH')) {
		$params = $ip_address;
		$ip_address = undef;
	}
	$self->_validate_update($hostnames, $ip_address, $params);
	my ($protocol) = 'https'; # default protocol is https to protect user_name / password
	if ($params->{protocol}) {
		$protocol = $params->{protocol};
	}
	if ($protocol eq 'https') {
		eval { require Net::HTTPS; };
		if ($@) {
			die("Cannot load Net::HTTPS\n");
		}
	}
	my ($update_url) = $protocol . "://$self->{dns_server}/nic/update?";
	if (exists $params->{system}) {
		$update_url .= 'system=' . $params->{system} . '&hostname=' . $hostnames;
	} else {
		$update_url .= 'hostname=' . $hostnames;
	}
	if (defined $ip_address) {
		$update_url .= '&myip=' . $ip_address;
	}
	if (exists $params->{wildcard}) {
		$update_url .= '&wildcard=' . $params->{wildcard};
	}
	if (exists $params->{mx}) {
		$update_url .= '&mx=' . $params->{mx};
	}
	if (exists $params->{backmx}) {
		$update_url .= '&backmx=' . $params->{backmx};
	}
	if (exists $params->{offline}) {
		$update_url .= '&offline=' . $params->{offline};
	}
	my ($response) = $self->_get($update_url);
	my ($content) = $response->content();
	my (@lines) = split /\015?\012/, $content;
	my ($result);
	my ($line);
	foreach $line (@lines) {
		if ($line =~ /^(\S+)\s+(\S.*)$/) {
			my ($code, $additional) = ($1, $2);
			if (($code eq 'good') || ($code eq 'nochg')) {
				if ($result) {
					unless ($result eq $additional) {
						die("Could not understand multi-line response\n$content\n");
					}
				} else {
					$result = $additional;
				}
			} else {
				$self->_error($code, $content);
			}
		} elsif ($line =~ /^(\S+)$/) {
			my ($code) = $1;
			$self->_error($code, $content);
		} else {
			die("Failed to parse response from '$update_url'\n$content\n");
		}
	}
	return ($result);
}

