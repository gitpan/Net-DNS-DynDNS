
use ExtUtils::MakeMaker;

unless ($] >= 5.010001) { die "perl version $] is unacceptable\n"; }

WriteMakefile(
                'NAME'          => 'Net::DNS::DynDNS',
                'VERSION_FROM'  => 'lib/Net/DNS/DynDNS.pm',
		'MIN_PERL_VERSION' => '5.10.0',
                'PREREQ_PM'     => {
                                'Test::More' => 0,
				'LWP' => 0,
				'English' => 0,
				'Carp' => 0,
				'HTTP::Cookies' => 0,
				'HTTP::Headers' => 0,
				'Net::HTTPS' => 0,
				'Crypt::SSLeay' => 0,
				'warnings' => 0,
				'strict' => 0,
                                        },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/DNS/DynDNS.pod', # retrieve abstract from module
       AUTHOR         => 'David Dick <ddick@cpan.org>') : ()),
    ($ExtUtils::MakeMaker::VERSION ge '6.30_00' ? # shamelessly copied this from Template Toolkit
      (LICENSE           => 'perl') : ()),
);
