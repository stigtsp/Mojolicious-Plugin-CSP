#!/usr/bin/env perl

use strict;
use warnings;

my $hash_ref = {
    argle => 'bargle',
    glop  => 'glyph',
};

#foreach (keys %{$hash_ref}) {
#    print "$_ = " . $hash_ref->{$_} . "\n";
#}

#map { print "$_ = " . $hash_ref->{$_} . "\n"; } keys %{$hash_ref};

my $string;

map { $string .=  "$_ = " . $hash_ref->{$_} . " \n"; } keys %{$hash_ref};

print STDERR $string;

exit 0;