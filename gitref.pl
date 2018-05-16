#! /usrbin/perl -w
use strict;

open my $fh, '-|', "git rev-parse HEAD" or die "can't open pipe to git: $!";
my $commit = <$fh>; chomp($commit);
close($fh) or warn "can't close pipe to git (ignored): $!";

open my $out, '>', $ARGV[0] or die "can't open output file $ARGV[0]: $!";
print $out "package pto3trace\n\n";
print $out "const CommitRef = \"", $commit, "\"\n";
close $out or warn "can't close output file $ARGV[1]: $!";