#! /usr/bin/perl -w
use strict;

open my $in, '<', $ARGV[0] or die "can't open input file $ARGV[0]: $!";
open my $out, '>', $ARGV[1] or die "can't open output file $ARGV[1]: $!";

my %ptoconds;

while (<$in>) {
    if (/\s+\d+ ((TCP|IP)::\S+)\s+\| (NEW )?([a-z0-9.-]+)$/o) {
        $ptoconds{$1} = $4;
    }
}


print $out "package main\n\n";

print $out "var tbToCond = map[string]string{\n";
foreach (keys %ptoconds) {
    print $out "  \"", $_, "\": \"", $ptoconds{$_}, "\",\n";   
}
print $out "}\n"