use strict; use warnings;
use Module::Build;

my $builder = Module::Build->new(
    sign              => 1,
    module_name       => 'Data::Password::Filter',
    license           => 'perl',
    dist_author       => q{Mohammad S Anwar <mohammad.anwar@yahoo.com>},
    dist_version_from => 'lib/Data/Password/Filter.pm',
    add_to_cleanup    => [ 'Data-Password-Filter-*' ],
    build_requires    => {
        'Test::More'  => 0,
        'Readonly'    => '1.03',
        'Mouse'       => '0.93',
    },
);

$builder->create_build_script();