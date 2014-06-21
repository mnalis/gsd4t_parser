#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-21
# parse strace.log created by "strace -e trace=open,read,write -e write=275 -e read=275 -tt -v -ff -o strace.log  -p 2029"
# and output it in SLCLog.gp2 alike format

use strict;
use autodie;

my $DEBUG = 4;
my $IN = 'data/strace3/strace.log.3382';
open my $fd, '<', $IN;

# strace format is like:
#12:02:02.092977 read(275, " ¢\0\4Ò\1\t\0L\235rá\n\24#\10", 2000) = 16
# | 00000  a0 a2 00 04 d2 01 09 00  4c 9d 72 e1 0a 14 23 08   ¢..Ò... L.rá..#. |


my $log = '';
while (<$fd>) {
    print "raw: $_" if $DEBUG > 8;
    next if (m{^(\d{2}:\d{2}:\d{2})(\.\d+) }); 	# FIXME: for now skip timestamp (and escaped read data, which we have in nicer hex format)
    next if (m{^\)});				# ignore end of syscall lines
    
    if (m{^\s+\|\s+[a-f0-9]+\s+(([a-f0-9]{2} ){1,8}( ([a-f0-9]{2} ){1,8}\s)?)}) {
      print "Start of hex $1\n" if $DEBUG > 5;
      $log .= $1;
    } else {
      die "unknown format for line: $_";
    }
}

close $fd;

print "log = $log\n" if $DEBUG > 6;
my @data = split ' ', $log;
undef $log;


# SLCLog.gp2 format is like:
# 21/06/2014 11:56:56.563 (0) A0 A2 00 0C FF 41 53 49 43 3A 20 47 53 44 34 54 03 DF B0 B3 

my $seen_eol1 = 0;
my $seen_eol2 = 1;
while (my $x = uc(shift @data)) {
  if ($seen_eol2) {
      $seen_eol2 = 0;
      print "xxxxxxx header FIXME ";
  }
  
  print "$x ";
  if ($seen_eol1) {
    $seen_eol1 = 0;
    if ($x eq 'B3') {
      print "\n";
      $seen_eol2 = 1;
    } else {
      die "invalid second terminator, expected b3 got $x";
    }
  }
  
  if ($x eq 'B0') {
    $seen_eol1 = 1;
  }
}
