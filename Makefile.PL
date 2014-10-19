use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;
use File::ShareDir::Install;

install_share dist => 'share';

WriteMakefile(
    NAME               => 'Data::Password::Filter',
    AUTHOR             => q{Mohammad S Anwar <mohammad.anwar@yahoo.com>},
    VERSION_FROM       => 'lib/Data/Password/Filter.pm',
    ABSTRACT_FROM      => 'lib/Data/Password/Filter.pm',
    LICENSE            => 'artistic_2',
    PL_FILES           => {},
    MIN_PERL_VERSION   => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker'     => 0,
        'File::ShareDir::Install' => '0.09',
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM     => {
        'autodie'          => 0,
        'Moo'              => 0,
        'namespace::clean' => 0,
        'File::Share'      => 0,
    },
    dist          => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean         => { FILES => 'Data-Password-Filter-*' },
    (eval { ExtUtils::MakeMaker->VERSION(6.46) } ? (META_MERGE => {
        'meta-spec' => { version => 2 },
        resources => {
            repository => {
                type => 'git',
                url  => 'https://github.com/Manwar/Data-Password-Filter.git',
                web  => 'https://github.com/Manwar/Data-Password-Filter',
            },
        }})
     : ()
    ),
);

package MY;
use File::ShareDir::Install 'postamble';
