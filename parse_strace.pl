#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-21
# parse strace.log created by "strace -e trace=open,read,write -e write=275 -e read=275 -tt -v -ff -o strace.log  -p 2029"
# and output it in SLCLog.gp2 alike format

use strict;
use autodie;

$| = 1;

my $DEBUG = 2;
my $IN = 'data/strace4/strace.log.3491';
open my $fd, '<', $IN;

# strace format is like:
#12:02:02.092977 read(275, " ¢\0\4Ò\1\t\0L\235rá\n\24#\10", 2000) = 16
# | 00000  a0 a2 00 04 d2 01 09 00  4c 9d 72 e1 0a 14 23 08   ¢..Ò... L.rá..#. |


my $last_hex = '';
my $lasttime = undef;
while (<$fd>) {
    print "raw: $_" if $DEBUG > 8;
    if (m{^(\d{2}:\d{2}:\d{2})(\.\d{3})\d* }) {
        $lasttime = "$1$2";
        print "Timestamp is now = $lasttime\n" if $DEBUG > 6;
        next;
    }
    next if (m{^\)});				# ignore end of syscall lines
    
    if (m{^\s+\|\s+[a-f0-9]+\s+(([a-f0-9]{2} ){1,8}( ([a-f0-9]{2} ){1,8}\s)?)}) {
      print "Start of hex $1\n" if $DEBUG > 5;
      $last_hex .= $1;
      if ($last_hex =~ /^(.*\s+b0\s+b3)(.*)$/i) {
          $last_hex = $2;
          my $packet = uc($1);
          print "Found whole packet: $packet\n" if $DEBUG > 2;
          
          $packet =~ s/\s{2,}/ /g;
          $packet =~ s/^\s+//;

          my $packet2 = $packet; $packet2 =~ s/\s//g;
          my $size = sprintf "%4x", (length $packet2) / 2;
          print "   size=$size\n" if $DEBUG > 3;
          # SLCLog.gp2 format is like:
          # 21/06/2014 11:56:56.563 (0) A0 A2 00 0C FF 41 53 49 43 3A 20 47 53 44 34 54 03 DF B0 B3
          print "00/00/0000 $lasttime (0) $packet\n";
      }
    } else {
      die "unknown format for line: $_";
    }
}
