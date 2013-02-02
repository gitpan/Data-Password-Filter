use strict; use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'Data::Password::Filter',
    AUTHOR        => q{Mohammad S Anwar <mohammad.anwar@yahoo.com>},
    VERSION_FROM  => 'lib/Data/Password/Filter.pm',
    ABSTRACT_FROM => 'lib/Data/Password/Filter.pm',
    dist          => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean         => { FILES => 'Data-Password-Filter-*' },
    PREREQ_PM     => {
        'Test::More' => 0,
        'Readonly'   => '1.03',
        'Mouse'      => '0.93',
    },
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
);