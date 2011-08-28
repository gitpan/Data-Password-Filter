#!perl

use strict; use warnings;
use Data::Password::Filter;
use Test::More tests => 1;

my $password = Data::Password::Filter->new();

is($password->score('Ab12345?'), '100%');