package Data::Password::Filter;

use Readonly;
use Carp;
use Data::Dumper;

use Mouse;
use Mouse::Util::TypeConstraints;
use Data::Password::Filter::Dictionary;

=head1 NAME

Data::Password::Filter - Interface to the password filter.

=head1 VERSION

Version 0.06

=cut

our $VERSION = '0.06';
Readonly my $STATUS =>
{
    'check_dictionary'        => 'Check Dictionary       :',
    'check_length'            => 'Check Length           :',
    'check_digit'             => 'Check Digit            :',
    'check_lowercase_letter'  => 'Check Lowercase Letter :',
    'check_uppercase_letter'  => 'Check Uppercase Letter :',
    'check_special_character' => 'Check Special Character:',
    'check_variation'         => 'Check Variation        :',
};

=head1 DESCRIPTION

The module is a simple attempt to convert an article written by Christopher Frenz on the topic
"The Development of a Perl-based Password Complexity Filter". However  I  took  the liberty to
add my flavour on top of it.

L<http://perl.sys-con.com/node/1911661>

=cut

type 'ZeroOrOne' => where { /^[01]$/ };
type 'Number'    => where { /^\d*$/ };
type 'FilePath'  => where { -f $_ };

has 'word_list' => ( is => 'ro', isa => 'ArrayRef', default => sub { \@Data::Password::Filter::Dictionary::LIST } );
has 'word_hash' => ( is => 'ro', isa => 'HashRef' , default => sub { \%Data::Password::Filter::Dictionary::HASH } );

has 'length'                => ( is => 'ro', isa => 'Number',    default => 8 );
has 'min_lowercase_letter'  => ( is => 'ro', isa => 'Number',    default => 1 );
has 'min_uppercase_letter'  => ( is => 'ro', isa => 'Number',    default => 1 );
has 'min_special_character' => ( is => 'ro', isa => 'Number',    default => 1 );
has 'min_digit'             => ( is => 'ro', isa => 'Number',    default => 1 );
has 'check_variation'       => ( is => 'ro', isa => 'ZeroOrOne', default => 1 );
has 'check_dictionary'      => ( is => 'ro', isa => 'ZeroOrOne', default => 1 );
has 'user_dictionary'       => ( is => 'ro', isa => 'FilePath' );

sub BUILD
{
    my $self = shift;
    if ($self->user_dictionary)
    {
        @{$self->{word_list}} = ();
        %{$self->{word_hash}} = ();

        open(DICTIONARY, '<:encoding(UTF-8)', $self->user_dictionary)
            or die("ERROR: Couldn't open user dictionary [".$self->user_dictionary."][$!]\n");
        while(my $word = <DICTIONARY>)
        {
            chomp($word);
            next if length($word) <= 3;
            push @{$self->{word_list}}, $word;
        }
        close(DICTIONARY);
        die("ERROR: Couldn't find word longer than 3 characters in the user dictionary [".$self->user_dictionary."]\n")
            unless scalar(@{$self->{word_list}});
        map { $self->{word_hash}->{lc($_)} = 1 } @{$self->{word_list}};
    }
}

=head1 CONSTRUCTOR

Below is the list parameters that can be passed to the constructor. None of the parameters are
mandatory. The format of user dictionary should be one word perl line. It  only  uses the word
longer than 3 characters from the user dictionary, if supplied.

    +-----------------------+----------------------------------------------------------------+
    | Key                   | Description                                                    |
    +-----------------------+----------------------------------------------------------------+
    | length                | Length of the password. Default is 8.                          |
    | min_lowercase_letter  | Minimum number of alphabets (a..z) in lowercase. Default is 1. |
    | min_uppercase_letter  | Minimum number of alphabets (A..Z) in uppercase. Default is 1. |
    | min_special_character | Minimum number of special characters. Default is 1.            |
    | min_digit             | Minimum number of digits (0..9). Default is 1.                 |
    | check_variation       | 1 or 0, depending whether checking variation. Default is 1.    |
    | check_dictionary      | 1 or 0, depending whether checking dictionary. Default is 1.   |
    | user_dictionary       | User supplied dictionary file location. Default use its own.   |
    +-----------------------+----------------------------------------------------------------+

=head1 SPECIAL CHARACTERS

Currently considers the following characters as special:

    !   "   #   $   %   &   '   (   \   |   )
    )   *   +   ,   -   .   /   :   ;   <   =
    >   ?   @   [   \   ]   ^   _   `   {   |
    }   ~

=head1 METHODS

=head2 strength()

Returns the strength of the given password.

    +----------------+------------+
    | Score (s)      | Strength   |
    +----------------+------------+
    | s <= 50%       | Very weak. |
    | 50% < s <= 70% | Weak.      |
    | 70% < s <= 90% | Good.      |
    | s > 90%        | Very good. |
    +----------------+------------+

    use strict; use warnings;
    use Data::Password::Filter;

    my $password = Data::Password::Filter->new();
    print "Strength: " . $password->strength('Ab12345?') . "\n";

=cut

sub strength
{
    my $self   = shift;
    my $passwd = shift;
    die("ERROR: Missing password.\n") unless (defined $passwd);

    return $self->_strength($passwd);
}

=head2 score()

Returns the score (percentage) of the given password  or  the  previous password for which the
strength has been calculated.

    use strict; use warnings;
    use Data::Password::Filter;

    my ($password);
    $password = Data::Password::Filter->new();
    print "Score: " . $password->score('Ab12345?') . "\n";

    $password = Data::Password::Filter->new();
    print "Strength: " . $password->strength('Ab54321?') . "\n";
    print "Score: " . $password->score() . "\n";

=cut

sub score
{
    my $self   = shift;
    my $passwd = shift;
    die("ERROR: Missing password.\n")
        unless (defined($passwd) || defined($self->{score}));

    $self->_strength($passwd) if defined $passwd;
    return $self->{score};
}

=head2 as_string()

Returns the filter detail.

    use strict; use warnings;
    use Data::Password::Filter;

    my $password = Data::Password::Filter->new();
    print "Strength: " . $password->strength('Ab12345?') . "\n";
    print "Score: " . $password->score('Ab12345?') . "\n";
    print $password->as_string() . "\n";

=cut

sub as_string
{
    my $self   = shift;
    return unless defined $self->{result};

    my $string = '';
    foreach (keys %{$STATUS})
    {
        if (defined($self->{result}->{$_}) && ($self->{result}->{$_}))
        {
            $string .= sprintf("%s %s\n", $STATUS->{$_}, '[PASS]');
        }
        else
        {
            $string .= sprintf("%s %s\n", $STATUS->{$_}, '[FAIL]');
        }
    }
    return $string;
}

sub _strength
{
    my $self   = shift;
    my $passwd = shift;

    $self->_checkDictionary($passwd) if $self->{check_dictionary};
    $self->_checkVariation($passwd)  if $self->{check_variation};
    $self->_checkLength($passwd);
    $self->_checkDigit($passwd);
    $self->_checkUppercaseLetter($passwd);
    $self->_checkLowercaseLetter($passwd);
    $self->_checkSpecialCharacter($passwd);

    my ($count, $score);
    $count = 0;
    foreach (keys %{$STATUS})
    {
        $count++ if (defined($self->{result}->{$_}) && ($self->{result}->{$_}));
    }

    $score = (100/(keys %{$STATUS})) * $count;
    $self->{score} = sprintf("%d%s", int($score), '%');

    if ($score <= 50)
    {
        return 'Very weak';
    }
    elsif (($score > 50) && ($score <= 70))
    {
        return 'Weak';
    }
    elsif (($score > 70) && ($score <= 90))
    {
        return 'Good';
    }
    elsif ($score > 90)
    {
        return 'Very good';
    }
}

sub _exists
{
    my $self = shift;
    my $word = shift;

    return 1 if exists($self->{'word_hash'}->{lc($word)});
    return 0;
}

sub _checkDictionary
{
    my $self   = shift;
    my $passwd = shift;

    $self->{result}->{'check_dictionary'} = !$self->_exists($passwd);
}

sub _checkLength
{
    my $self   = shift;
    my $passwd = shift;

    $self->{result}->{'check_length'} = !(length($passwd) < $self->{length});
}

sub _checkDigit
{
    my $self   = shift;
    my $passwd = shift;

    my $count = 0;
    $count++ while ($passwd =~ /\d/g);

    $self->{result}->{'check_digit'} = !($count < $self->{min_digit});
}

sub _checkLowercaseLetter
{
    my $self   = shift;
    my $passwd = shift;

    my $count = 0;
    $count++ while ($passwd =~ /[a-z]/g);

    $self->{result}->{'check_lowercase_letter'} = !($count < $self->{min_lowercase_letter});
}

sub _checkUppercaseLetter
{
    my $self   = shift;
    my $passwd = shift;

    my $count = 0;
    $count++ while ($passwd =~ /[A-Z]/g);

    $self->{result}->{'check_uppercase_letter'} = !($count < $self->{min_uppercase_letter});
}

sub _checkSpecialCharacter
{
    my $self   = shift;
    my $passwd = shift;

    my $count = 0;
    $count++ while($passwd=~/!|"|#|\$|%|&|'|\(|\)|\*|\+|,|-|\.|\/|:|;|<|=|>|\?|@|\[|\\|]|\^|_|`|\{|\||}|~/g);

    $self->{result}->{'check_special_character'} = !($count < $self->{min_special_character});
}

sub _checkVariation
{
    my $self   = shift;
    my $passwd = shift;

    unless (defined($self->{result}->{'check_dictionary'}) && ($self->{result}->{'check_dictionary'}))
    {
        $self->{result}->{'check_variation'} = 0;
        return;
    }

    my ($regexp, @_passwd);
    for (my $i = 0; $i <= (length($passwd)-1); $i++)
    {
        pos($passwd) = 0;
        while ($passwd =~ /(\w)/gc)
        {
            my $char = $1;
            my $spos = pos($passwd)-1;
            $char = '.' if ($spos == $i);
            (defined($_passwd[$i]))
            ?
            ($_passwd[$i] .= $char)
            :
            ($_passwd[$i] = $char);
        }
        $regexp .= $_passwd[$i] . '|';
    }
    $regexp =~ s/\|$//g;

    foreach (@{$self->{'word_list'}})
    {
        ($self->{result}->{'check_variation'} = 0 && return) if /$regexp/i;
    }

    $self->{result}->{'check_variation'} = 1;
}

=head1 AUTHOR

Mohammad S Anwar, C<< <mohammad.anwar at yahoo.com> >>

=head1 BUGS

Please  report  any bugs or feature requests to C<bug-data-password-filter at rt.cpan.org>, or
through the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Data-Password-Filter>.
I will be notified and then you'll automatically be notified of progress on your bug as I make
changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Data::Password::Filter

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Data-Password-Filter>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Data-Password-Filter>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Data-Password-Filter>

=item * Search CPAN

L<http://search.cpan.org/dist/Data-Password-Filter/>

=back

=head1 ACKNOWLEDGEMENT

Christopher Frenz, author of "Visual Basic and Visual Basic .NET for Scientists and Engineers"
(Apress) and "Pro Perl Parsing" (Apress).

=head1 LICENSE AND COPYRIGHT

Copyright 2011-13 Mohammad S Anwar.

This  program  is  free  software; you can redistribute it and/or modify it under the terms of
either:  the  GNU  General Public License as published by the Free Software Foundation; or the
Artistic License.

See http://dev.perl.org/licenses/ for more information.

=head1 DISCLAIMER

This  program  is  distributed in the hope that it will be useful,  but  WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=cut

__PACKAGE__->meta->make_immutable;
no Mouse; # Keywords are removed from the Data::Password::Filter package
no Mouse::Util::TypeConstraints;

1; # End of Data::Password::Filter
