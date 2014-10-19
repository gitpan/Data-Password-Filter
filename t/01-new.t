#!perl

use strict; use warnings;
use Data::Password::Filter;
use Test::More tests => 18;

eval { Data::Password::Filter->new('length' => 'a') };
like($@, qr/isa check for "length" failed/);

eval { Data::Password::Filter->new('min_lowercase_letter' => 'a') };
like($@, qr/isa check for "min_lowercase_letter" failed/);

eval { Data::Password::Filter->new('min_uppercase_letter' => 'a') };
like($@, qr/isa check for "min_uppercase_letter" failed/);

eval { Data::Password::Filter->new('min_special_character' => 'a') };
like($@, qr/isa check for "min_special_character" failed/);

eval { Data::Password::Filter->new('min_digit' => 'a') };
like($@, qr/isa check for "min_digit" failed/);

eval { Data::Password::Filter->new('min_lowercase_letter' => -1) };
like($@, qr/isa check for "min_lowercase_letter" failed/);

eval { Data::Password::Filter->new('min_uppercase_letter' => -1) };
like($@, qr/isa check for "min_uppercase_letter" failed/);

eval { Data::Password::Filter->new('min_special_character' => -1) };
like($@, qr/isa check for "min_special_character" failed/);

eval { Data::Password::Filter->new('min_digit' => -1) };
like($@, qr/isa check for "min_digit" failed/);

eval { Data::Password::Filter->new('check_variation' => 'a') };
like($@, qr/isa check for "check_variation" failed/);

eval { Data::Password::Filter->new('check_variation' => -1) };
like($@, qr/isa check for "check_variation" failed/);

eval { Data::Password::Filter->new('check_variation' => 2) };
like($@, qr/isa check for "check_variation" failed/);

eval { Data::Password::Filter->new('check_dictionary' => 'a') };
like($@, qr/isa check for "check_dictionary" failed/);

eval { Data::Password::Filter->new('check_dictionary' => -1) };
like($@, qr/isa check for "check_dictionary" failed/);

eval { Data::Password::Filter->new('check_dictionary' => 2) };
like($@, qr/isa check for "check_dictionary" failed/);

eval { Data::Password::Filter->new('user_dictionary' => 'DictionaryDoesNotExists.txt') };
like($@, qr/isa check for "user_dictionary" failed/);

eval { Data::Password::Filter->new('user_dictionary' => 2) };
like($@, qr/isa check for "user_dictionary" failed/);

eval { Data::Password::Filter->new('user_dictionary' => 't/DictionaryWithNoWord.txt') };
like($@, qr/ERROR: Couldn't find word longer than 3 characters in the dictionary/);
