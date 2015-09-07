#!/usr/bin/perl -w
# extract only MID8 data from SLCLog.gp2.human.txt (produced via "sirfbin_gp2_to_human.pl SLCLog.gp2) 
# and fake it in raw4t format, so we can test raw4t_gp2_to_human.pl parser

use strict;
# lines looks like this:
# 16:21:38.147 GPSD knows MID 0x08 --  subframe data MID 8 (extract leap-second from this) -- hex 00 1D 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 00 00 00 0A 89 DD 83 81 46 78 F1 C6 A7 7D 3A 02 8A C0 06 10

while (<>) {
  next unless /^(.*) GPSD knows MID 0x08\h*--\h*subframe data MID 8.*-- hex\h*(..)\h+(..)\h+(.*)$/;
  my $time=$1; my $cnt=$2; my $SVID=$3; my $hex=$4;
  print "00/00/0009 $time (0) 85 $cnt 01 $SVID FF FF FF FF FF FF FF $hex\n";
}