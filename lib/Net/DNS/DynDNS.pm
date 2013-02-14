## no critic (RequireRcsKeywords)
# here's 20 cents kid, go buy yourself a real revision control system

package Net::DNS::DynDNS;

use LWP();
use HTTP::Cookies();
use HTTP::Headers();
use Carp();
use English qw(-no_match_vars);
use warnings;
use strict;
use feature ':5.10';
our $VERSION = '0.99';

my $DEFAULT_TIMEOUT                      = '60';
my $NUMBER_OF_OCTETS_IN_IP_ADDRESS       = '4';
my $MAXIMUM_VALUE_OF_AN_OCTET            = '256';
my $FIRST_BYTE_OF_10_PRIVATE_RANGE       = '10';
my $FIRST_BYTE_OF_172_16_PRIVATE_RANGE   = '172';
my $SECOND_BYTE_OF_172_16_PRIVATE_RANGE  = '16';
my $FIRST_BYTE_OF_192_168_PRIVATE_RANGE  = '192';
my $SECOND_BYTE_OF_192_168_PRIVATE_RANGE = '168';
my $LOCALHOST_RANGE                      = '127';
my $MULTICAST_RESERVED_LOWEST_RANGE      = '224';

sub new {
    my ( $class, $user_name, $password, $params ) = @_;
    my ($self)    = {};
    my ($timeout) = $DEFAULT_TIMEOUT;
    if ( ( ref $user_name ) && ( ref $user_name eq 'SCALAR' ) ) {
        if ( not( ( ref $password ) && ( ref $password eq 'SCALAR' ) ) ) {
            die "No password supplied\n";
        }
    }
    elsif ( ( ref $user_name ) && ( ( ref $user_name ) eq 'HASH' ) ) {
        $params    = $user_name;
        $user_name = undef;
        $password  = undef;
    }
    if ( exists $params->{timeout} ) {
        if ( ( $params->{timeout} ) && ( $params->{timeout} =~ /^\d+$/xsm ) ) {
            $timeout = $params->{timeout};
        }
        else {
            die "The 'timeout' parameter must be a number\n";
        }
    }
    my ($name) = "Net::DNS::DynDNS $VERSION "
      ;    # a space causes the default LWP User Agent to be appended.
    if ( exists $params->{user_agent} ) {
        if ( ( $params->{user_agent} ) && ( $params->{user_agent} =~ /\S/xsm ) )
        {
            $name = $params->{user_agent};
        }
    }
    my ($ua) = LWP::UserAgent->new( timeout => $timeout )
      ; # no sense in using keep_alive => 1 because updates and checks are supposed to happen infrequently
    $ua->agent($name);
    my ($cookie_jar) = HTTP::Cookies->new( hide_cookie2 => 1 );
    $ua->cookie_jar($cookie_jar);
    $ua->requests_redirectable( ['GET'] );
    $self->{_ua} = $ua;
    my ($headers) = HTTP::Headers->new();

    if ( ($user_name) && ($password) ) {
        $headers->authorization_basic( $user_name, $password );
    }
    $self->{_headers}   = $headers;
    $self->{server}     = $params->{server} || 'dyndns.org';
    $self->{dns_server} = $params->{dns_server} || 'members.dyndns.org';
    $self->{check_ip}   = $params->{check_ip} || 'checkip.dyndns.org';
    bless $self, $class;
    $self->update_allowed(1);
    return ($self);
}

sub _get {
    my ( $self, $uri ) = @_;
    my ($ua)      = $self->{_ua};
    my ($headers) = $self->{_headers};
    my ($request) = HTTP::Request->new( 'GET' => $uri, $headers );
    my ($response);
    eval {
        local $SIG{'ALRM'} = sub { die "Timeout\n"; };
        alarm $ua->timeout();
        $response = $ua->request($request);
        alarm 0;
        1;
    } or do {
        die "Failed to get a response from '$uri':$EVAL_ERROR\n";
    };
    return ($response);
}

sub default_ip_address {
    my ( $proto, $params ) = @_;
    my ($self);
    if ( ref $proto ) {
        $self = $proto;
    }
    else {
        $self = $proto->new($params);
    }
    my ($check_ip_uri) = $self->_check_ip_address_uri($params);

    # user_name / password is not necessary for checkip.
    # therefore don't send user_name / password

    my ($headers) = $self->{_headers};
    my ( $user_name, $password ) = $headers->authorization_basic();
    $headers->remove_header('Authorization');

    my ($response);
    my ($network_error);
    eval { $response = $self->_get($check_ip_uri); } or do {
        $network_error = $EVAL_ERROR;
    };

    # restore user_name / password

    if ( ($user_name) && ($password) ) {
        $headers->authorization_basic( $user_name, $password );
    }

    if ($network_error) {
        Carp::croak($network_error);
    }
    return $self->_parse_ip_address( $check_ip_uri, $response );
}

sub _check_ip_address_uri {
    my ( $self, $params ) = @_;
    my ($protocol) = 'http'
      ; # default protocol is http because no user_name / passwords are required
    if ( exists $params->{protocol} ) {
        if ( ( defined $params->{protocol} ) && ( $params->{protocol} ) ) {
            $params->{protocol} = lc( $params->{protocol} );
            if (   ( $params->{protocol} ne 'http' )
                && ( $params->{protocol} ne 'https' ) )
            {
                die
                  "The 'protocol' parameter must be one of 'http' or 'https'\n";
            }
        }
        else {
            die "The 'protocol' parameter must be one of 'http' or 'https'\n";
        }
        $protocol = $params->{protocol};
    }
    if ( $protocol eq 'https' ) {
        eval { require Net::HTTPS; } or do {
            die "Cannot load Net::HTTPS\n";
        };
    }
    return $protocol . '://' . $self->{check_ip};
}

sub _parse_ip_address {
    my ( $self, $check_ip_uri, $response ) = @_;
    my ($ip_address);
    if ( $response->is_success() ) {
        my ($content) = $response->content();
        if ( $content =~ /Current\sIP\sAddress:\s(\d+.\d+.\d+.\d+)/xsm ) {
            $ip_address = $1;
        }
        else {
            die "Failed to parse response from '$check_ip_uri'\n$content\n";
        }
    }
    else {
        my ($content) = $response->content();
        if ( $content =~ /Can't\sconnect\sto\s$self->{check_ip}/xsm ) {
            die "Failed to connect to '$check_ip_uri'\n";
        }
        else {
            die "Failed to get a success type response from '$check_ip_uri'\n";
        }
    }
    return ($ip_address);
}

sub _validate_update {
    my ( $self, $hostnames, $ip_address, $params ) = @_;
    my ($headers) = $self->{_headers};
    my ( $user_name, $password ) = $headers->authorization_basic();
    if ( not $self->update_allowed() ) {
        die
"$self->{server} has forbidden updates until the previous error is corrected\n";
    }
    if ( not( ($user_name) && ($password) ) ) {
        die "Username and password must be supplied for an update\n";
    }
    if ( not($hostnames) ) {
        die "The update method must be supplied with a hostname\n";
    }
    if (
        not( $hostnames =~
            /^(?:(?:[\p{IsAlphabetic}\-]+[.])+[\p{IsAlphabetic}\-]+,?)+$/xsm )
      )
    {
        die
"The hostnames do not seem to be in a valid format.  Try 'test.$self->{server}'\n";
    }
    $self->_validate_ip_address($ip_address);
    if ( ( ref $params ) && ( ( ref $params ) eq 'HASH' ) ) {
        $self->_check_wildcard($params);
        $self->_check_mx($params);
        $self->_check_backmx($params);
        $self->_check_offline($params);
        if ( exists $params->{protocol} ) {
            $self->_check_protocol($params);
        }
        else {
            $params->{protocol} = 'https';
        }
    }
    elsif ($params) {
        die "Extra parameters must be passed in as a reference to a hash\n";
    }
    return;
}

sub _validate_ip_address {
    my ( $self, $ip_address ) = @_;
    if ( defined $ip_address ) {
        my (@bytes) = split /[.]/xsm, $ip_address;
        if ( ( scalar @bytes ) != $NUMBER_OF_OCTETS_IN_IP_ADDRESS ) {
            die "Bad IP address\n";
        }
        foreach my $byte (@bytes) {
            if ( not( $byte =~ /^\d+$/xsm ) ) {
                die "Bad IP address.  Each byte must be numeric\n";
            }
            if ( ( $byte >= $MAXIMUM_VALUE_OF_AN_OCTET ) || ( $byte < 0 ) ) {
                die "Bad IP address.  Each byte must be within 0-255\n";
            }
        }
        if (
               ( $bytes[0] == 0 )
            || ( $bytes[0] == $LOCALHOST_RANGE )
            || ( $bytes[0] == $FIRST_BYTE_OF_10_PRIVATE_RANGE )
            || (   ( $bytes[0] == $FIRST_BYTE_OF_172_16_PRIVATE_RANGE )
                && ( $bytes[1] == $SECOND_BYTE_OF_172_16_PRIVATE_RANGE ) )
            ||    # private
            (
                   ( $bytes[0] == $FIRST_BYTE_OF_192_168_PRIVATE_RANGE )
                && ( $bytes[1] == $SECOND_BYTE_OF_192_168_PRIVATE_RANGE )
            )
            ||    # private
            ( $bytes[0] >= $MULTICAST_RESERVED_LOWEST_RANGE )
          )       # multicast && reserved
        {
            die
"Bad IP address.  The IP address is in a range that is not publically addressable\n";
        }
    }
}

sub _check_wildcard {
    my ( $self, $params ) = @_;
    if ( exists $params->{wildcard} ) {
        if ( ( defined $params->{wildcard} ) && ( $params->{wildcard} ) ) {
            $params->{wildcard} = uc( $params->{wildcard} );
            if (   ( $params->{wildcard} ne 'ON' )
                && ( $params->{wildcard} ne 'OFF' )
                && ( $params->{wildcard} ne 'NOCHG' ) )
            {
                die
"The 'wildcard' parameter must be one of 'ON','OFF' or 'NOCHG'\n";
            }
        }
        else {
            die
              "The 'wildcard' parameter must be one of 'ON','OFF' or 'NOCHG'\n";
        }
    }
}

sub _check_mx {
    my ( $self, $params ) = @_;
    if ( exists $params->{mx} ) {
        if ( ( defined $params->{mx} ) && ( $params->{mx} ) ) {
            if (
                not( $params->{mx} =~
/^(?:(?:[\p{IsAlphabetic}\-]+[.])+[\p{IsAlphabetic}\-]+,?)+$/xsm
                )
              )
            {
                die
"The 'mx' parameter does not seem to be in a valid format.  Try 'test.$self->{server}'\n";
            }
        }
        else {
            die
"The 'mx' parameter must be a valid fully qualified domain name\n";
        }
    }
    else {
        if ( exists $params->{backmx} ) {
            die
"The 'backmx' parameter cannot be set without specifying the 'mx' parameter\n";
        }
    }
}

sub _check_backmx {
    my ( $self, $params ) = @_;
    if ( exists $params->{backmx} ) {
        if ( ( defined $params->{backmx} ) && ( $params->{backmx} ) ) {
            $params->{backmx} = uc( $params->{backmx} );
            if (   ( $params->{backmx} ne 'YES' )
                && ( $params->{backmx} ne 'NO' ) )
            {
                die "The 'backmx' parameter must be one of 'YES' or 'NO'\n";
            }
        }
        else {
            die "The 'backmx' parameter must be one of 'YES' or 'NO'\n";
        }
    }
}

sub _check_offline {
    my ( $self, $params ) = @_;
    if ( exists $params->{offline} ) {
        if ( ( defined $params->{offline} ) && ( $params->{offline} ) ) {
            $params->{offline} = uc( $params->{offline} );
            if (   ( $params->{offline} ne 'YES' )
                && ( $params->{offline} ne 'NO' ) )
            {
                die "The 'offline' parameter must be one of 'YES' or 'NO'\n";
            }
        }
        else {
            die "The 'offline' parameter must be one of 'YES' or 'NO'\n";
        }
    }
}

sub _check_protocol {
    my ( $self, $params ) = @_;
    if ( ( defined $params->{protocol} ) && ( $params->{protocol} ) ) {
        $params->{protocol} = lc( $params->{protocol} );
        if (   ( $params->{protocol} ne 'http' )
            && ( $params->{protocol} ne 'https' ) )
        {
            die "The 'protocol' parameter must be one of 'http' or 'https'\n";
        }
    }
    else {
        die "The 'protocol' parameter must be one of 'http' or 'https'\n";
    }
}

sub update_allowed {
    my ( $self, $allowed ) = @_;
    my ($old);
    if ( ( exists $self->{update_allowed} ) && ( $self->{update_allowed} ) ) {
        $old = $self->{update_allowed};
    }
    if ( defined $allowed ) {
        $self->{update_allowed} = $allowed;
    }
    return ($old);
}

sub _error {
    my ( $self, $code, $content ) = @_;
    $self->update_allowed(0);
    given ($code) {
        when ('badauth') {
            $self->{error} =
              'The username and password pair do not match a real user';
        }
        when ('!donator') {
            $self->{error} =
'An option available only to credited users (such as offline URL) was specified, but the user is not a credited user';
        }
        when ('notfqdn') {
            $self->{error} =
'The hostname specified is not a fully-qualified domain name (not in the form hostname.dyndns.org or domain.com)';
        }
        when ('nohost') {
            $self->{error} =
              'The hostname specified does not exist in this user account';
        }
        when ('numhost') {
            $self->{error} =
              'Too many hosts (more than 20) specified in an update';
        }
        when ('abuse') {
            $self->{error} =
              'The hostname specified is blocked for update abuse';
        }
        when ('badagent') {
            $self->{error} =
              'The user agent was not sent or HTTP method is not permitted';
        }
        when ('dnserr') {
            $self->{error} = 'DNS error encountered';
        }
        when ('911') {
            $self->{error} =
              'There is a problem or scheduled maintenance on our side';
        }
        default {
            $self->{error} = "Unknown error:$code";
        }
    }
    die "$self->{error}\n";
}

sub update {
    my ( $self, $hostnames, $ip_address, $params ) = @_;
    if ( ( ref $ip_address ) && ( ref $ip_address eq 'HASH' ) ) {
        $params     = $ip_address;
        $ip_address = undef;
    }
    $self->_validate_update( $hostnames, $ip_address, $params );
    my ($protocol) =
      'https';    # default protocol is https to protect user_name / password
    if ( $params->{protocol} ) {
        $protocol = $params->{protocol};
    }
    if ( $protocol eq 'https' ) {
        eval { require Net::HTTPS; } or do {
            die "Cannot load Net::HTTPS\n";
        };
    }
    my $update_uri =
      $protocol . "://$self->{dns_server}/nic/update?hostname=" . $hostnames;
    if ( defined $ip_address ) {
        $update_uri .= '&myip=' . $ip_address;
    }
    if ( exists $params->{wildcard} ) {
        $update_uri .= '&wildcard=' . $params->{wildcard};
    }
    if ( exists $params->{mx} ) {
        $update_uri .= '&mx=' . $params->{mx};
    }
    if ( exists $params->{backmx} ) {
        $update_uri .= '&backmx=' . $params->{backmx};
    }
    if ( exists $params->{offline} ) {
        $update_uri .= '&offline=' . $params->{offline};
    }
    my $response = $self->_get($update_uri);
    my $content  = $response->content();
    my $result   = $self->_parse_content( $update_uri, $content );
    return $result;
}

sub _parse_content {
    my ( $self, $update_uri, $content ) = @_;
    my @lines = split /\015?\012/xsm, $content;
    my $result;
    foreach my $line (@lines) {
        if (
            $line =~ m{ 
			( \S + )  # response code
			\s+
			(\S.*) $ # ip address (possible)
			}xsm
          )
        {
            my ( $code, $additional ) = ( $1, $2 );
            if ( ( $code eq 'good' ) || ( $code eq 'nochg' ) ) {
                if ($result) {
                    if ( $result ne $additional ) {
                        die
"Could not understand multi-line response\n$content\n";
                    }
                }
                else {
                    $result = $additional;
                }
            }
            else {
                $self->_error( $code, $content );
            }
        }
        elsif (
            $line =~ m{
                ^ ( \S + ) $ # if this line of the response is a single code word
              }xsm
          )
        {
            my ($code) = $1;
            $self->_error( $code, $content );
        }
        else {
            die "Failed to parse response from '$update_uri'\n$content\n";
        }
    }
    return $result;
}

1;
