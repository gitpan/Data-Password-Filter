#!perl

use strict; use warnings;
use Data::Password::Filter;
use Test::More tests => 2;

my $password = Data::Password::Filter->new();

is($password->score('Ab12345?'), '100%');

$password = Data::Password::Filter->new();
$password->strength('Ab12345?');
is($password->score(), '100%');