#!perl

use strict; use warnings;
use Data::Password::Filter;
use Test::More tests => 18;

eval { Data::Password::Filter->new('length' => 'a') };
like($@, qr/Attribute \(length\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_lowercase_letter' => 'a') };
like($@, qr/Attribute \(min_lowercase_letter\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_uppercase_letter' => 'a') };
like($@, qr/Attribute \(min_uppercase_letter\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_special_character' => 'a') };
like($@, qr/Attribute \(min_special_character\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_digit' => 'a') };
like($@, qr/Attribute \(min_digit\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_lowercase_letter' => -1) };
like($@, qr/Attribute \(min_lowercase_letter\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_uppercase_letter' => -1) };
like($@, qr/Attribute \(min_uppercase_letter\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_special_character' => -1) };
like($@, qr/Attribute \(min_special_character\) does not pass the type constraint/);

eval { Data::Password::Filter->new('min_digit' => -1) };
like($@, qr/Attribute \(min_digit\) does not pass the type constraint/);

eval { Data::Password::Filter->new('check_variation' => 'a') };
like($@, qr/Attribute \(check_variation\) does not pass the type constraint/);

eval { Data::Password::Filter->new('check_variation' => -1) };
like($@, qr/Attribute \(check_variation\) does not pass the type constraint/);

eval { Data::Password::Filter->new('check_variation' => 2) };
like($@, qr/Attribute \(check_variation\) does not pass the type constraint/);

eval { Data::Password::Filter->new('check_dictionary' => 'a') };
like($@, qr/Attribute \(check_dictionary\) does not pass the type constraint/);

eval { Data::Password::Filter->new('check_dictionary' => -1) };
like($@, qr/Attribute \(check_dictionary\) does not pass the type constraint/);

eval { Data::Password::Filter->new('check_dictionary' => 2) };
like($@, qr/Attribute \(check_dictionary\) does not pass the type constraint/);

eval { Data::Password::Filter->new('user_dictionary' => 'DictionaryDoesNotExists.txt') };
like($@, qr/Attribute \(user_dictionary\) does not pass the type constraint/);

eval { Data::Password::Filter->new('user_dictionary' => 2) };
like($@, qr/Attribute \(user_dictionary\) does not pass the type constraint/);

eval { Data::Password::Filter->new('user_dictionary' => 't/DictionaryWithNoWord.txt') };
like($@, qr/ERROR: Couldn't find word longer than 3 characters in the user dictionary/);