#!/usr/bin/perl -w
# 
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-07-14
# parses raw SiRF binary commands (like SLCLog.bin) and creates SLCLog.gp2 text file. 
# Note: depends od A0A2 / B0B3, so only SiRF OSP (and perhaps enc4t) can be converted.

#
# Usage: ./sirfbin_to_gp2.pl < SLCLog.bin > SLCLog.gp2
#

use strict;
use autodie;

my $DEBUG = 0;

$|=1;

my $has_a0=0;
my $has_a2=0;
my $has_b0=1;
my $has_b3=1;

my $count2=0; my $count1=0;
my $out = '';
while (read (STDIN, my $c, 1)) {
  my $x = uc unpack 'H*', $c;

  $out .= "$x ";  
  
  if ($x eq 'A0') {
      if ($has_a0) { die "huh? double incoming A0" }
      if ($has_a2) { die "huh? already has A2, now incoming A0" }
      if ($has_b0 and $has_b3) { $has_a0 = 1; $has_a2 = 0} 
      else { warn "new packet starting without previous packet ending" }
  } elsif ($x eq 'A2') {
      if ($has_a0 and $has_b0 and $has_b3) { $has_a2 = 1; $has_b0 = 0; $has_b3 = 0; } 
      else { die "something strange with A2" }
  } elsif ($x eq 'B0') {
      if ($has_b0) { die "huh? double incoming B0" }
      if ($has_b3) { die "huh? already has B3, now incoming B0" }
      if ($has_a0 and $has_a2) { $has_b0 = 1} 
      else { warn "packet ending before starting" }
  } elsif ($x eq 'B3') {
      if ($has_b0 and $has_a0 and $has_a2) { $has_b3 = 1; $has_a0 = 0; $has_a2 = 0; } 
      else { die "something strange with B3" }
  } else {
      # regular payload byte..
  }
  
  $DEBUG && print "char=0x$x A0A2=$has_a0$has_a2 B0B3=$has_b0$has_b3 out=$out\n" ;
  
  if ($has_b0 and $has_b3 and !$has_a0 and !$has_a2) {	# packet ended, print it
      printf "00/00/0007 00:00:%02d.%03d (0) $out\n", $count2, $count1;
      $out = '';
  }
  if ($count1++ > 999) { $count2++; $count1=0; }
  
}
