use strict;
use warnings;

use 5.010000;

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Authen::NZigovt',
    AUTHOR              => q{Grant McLean <grantm@catalyst.net.nz>},
    VERSION_FROM        => 'lib/Authen/NZigovt.pm',
    ABSTRACT_FROM       => 'lib/Authen/NZigovt.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More'               => 0,
        'XML::Generator'           => 0,
        'XML::LibXML'              => 0,
        'URI'                      => 0,
        'LWP'                      => 0,
        'WWW::Curl'                => 0,
        'Crypt::OpenSSL::RSA'      => 0,
        'Crypt::OpenSSL::X509'     => 0,
        'Digest::SHA1'             => 0,
        'IO::Compress::RawDeflate' => 0,
    },
    EXE_FILES           => [ qw(bin/nzigovt) ],
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Authen-NZigovt-*' },
);
