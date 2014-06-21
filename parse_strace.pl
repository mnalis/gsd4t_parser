#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-21
# parse strace.log created by "strace -e trace=open,read,write -e write=275 -e read=275 -tt -v -ff -o strace.log  -p 2029"

use strict;
use autodie;

my $DEBUG = 2;
my $IN = 'data/strace3/strace.log.3382';
open my $fd, '<', $IN;

# format is like:
#12:02:02.092977 read(275, " ¢\0\4Ò\1\t\0L\235rá\n\24#\10", 2000) = 16
# | 00000  a0 a2 00 04 d2 01 09 00  4c 9d 72 e1 0a 14 23 08   ¢..Ò... L.rá..#. |


while (<$fd>) {
    print "raw: $_" if $DEBUG > 8;
    next if (m{^(\d{2}:\d{2}:\d{2})(\.\d+) }); 	# FIXME: for now skip timestamp (and escaped read data, which we have in nicer hex format)
    next if (m{^\)});				# ignore end of syscall lines
    
    if (m{^\s+\|\s+[a-f0-9]+\s+(([a-f0-9]{2} ){1,8}( ([a-f0-9]{2} ){1,8})?)}) {
      print "Start of hex $1\n";
    } else {
      die "unknown format for line: $_";
    }
    #die;	# FIXME - test just first line
}
