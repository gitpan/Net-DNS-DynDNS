
use ExtUtils::MakeMaker;

WriteMakefile(
                'NAME'          => 'Net::DNS::DynDNS',
                'VERSION_FROM'  => 'lib/Net/DNS/DynDNS.pm',
                'PREREQ_PM'     => {
                                'Test::More' => 0,
				'LWP' => 0,
				'HTTP::Cookies' => 0,
				'HTTP::Headers' => 0,
				'Net::HTTPS' => 0,
                                        },
);
