#!/usr/bin/perl
# 
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-21
# parse SLCLog.gp2 and create raw binary data (for passing to gpsd or similar)
#
# Usage: ./gp2_to_bin.pl data/2/SLCLog.gp2 > slclog.bin
#


while (<>) {
  s/^.*\(0\) //; 	# remote timestamps etc
  s/\s+//g; 		# no whitespace allowd for pack
  print pack "H*", $_;
}
