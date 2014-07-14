#!/usr/bin/perl -w
# 
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-07-14
# parses raw SiRF binary commands (like SLCLog.bin) and creates SLCLog.gp2 text file. 
# Note: depends od A0A2 / B0B3, so only SiRF OSP (and perhaps enc4t) can be converted.

# FIXME - sometimes it incorrectly splits into two packets when (B0 B3 found in payload). We could use packet size for raw binary SiRF OSP to fix that, but then this script could not process enc4t (it would need separate script). probably should be done, but can't bother right now, as it is easy to manually join a line or two in broken output
#
# Usage: ./sirfbin_to_gp2.pl < SLCLog.bin > SLCLog.gp2
#

use strict;
use autodie;

my $DEBUG = 0;

#$|=1;

my $count2=0; my $count1=0;
my $out = '';
my $last_x = '';
while (read (STDIN, my $c, 1)) {
  my $x = uc unpack 'H*', $c;
  $out .= "$x ";  
  
  $DEBUG && print "char=0x$x out=$out\n" ;
  
  if ($x eq 'B3' and $last_x eq 'B0') {		# packet ended, print it
      printf "00/00/0007 00:00:%02d.%03d (0) $out\n", $count2, $count1;
      $out = '';
  }
  if ($count1++ > 999) { $count2++; $count1=0; }
  $last_x = $x;
}
