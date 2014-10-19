#!perl

use Test::More tests => 2;

BEGIN {
    use_ok('Data::Password::Filter')         || print "Bail out!";
    use_ok('Data::Password::Filter::Params') || print "Bail out!";
}
