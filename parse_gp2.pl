#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-21
# parse SLCLog.gp2 created by GSD4t on Samsung Galaxy S2 running CyanogenMod9
#
# Usage: ./parse_gp2.pl data/2/SLCLog.gp2
#
use strict;
use autodie;
use feature "switch";

my $DEBUG = 2;

# format is like:
# 21/06/2014 00:02:23.287 (0) A0 A2 00 0C FF 41 53 49 43 3A 20 47 53 44 34 54 03 DF B0 B3 
# A0 A2 -- leadin
# 00 0C -- length
# FF -- command (MID)
# 41....43 -- rest of payload
# 03 DF -- plain checksum (MID + payload)
# B0 B3 -- leadout

while (<>) {
  if (m{^(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2})(\.\d{3}) \(0\) A0 A2 ([A-F0-9 ]+) B0 B3\s*}) {
    print "raw: $_" if $DEBUG > 8;
    my $date = $1; my $time = $2; my $msec=$3; 
    my @data = split ' ', $4;
    my $pkt_length = hex((shift @data) . (shift @data));
    my $MID = shift @data;
    
    my $checksum = pop @data; $checksum = hex((pop @data) . $checksum);
    my $verify = hex($MID); 
    foreach my $x (@data) { $verify += hex($x); }
    $verify = $verify & 0x7FFF;	# 15 bit only? without it we sometimes die on mismatch like 07F5 / 87F5
    
    my $rest = join '', @data;
    if ((length "$MID$rest") != $pkt_length * 2) { die "invalid packet length $pkt_length != " . (length "$MID$rest")/2 . " in $_" }

    print "  packet $time (len=$pkt_length) $MID $rest (cksum $checksum/$verify)\n" if $DEBUG > 6;
    if ($checksum != $verify) { die "invalid checksum $checksum != $verify for $_" }
    
    print "  $time $MID $rest\n" if $DEBUG > 3;

    given ($MID) {
      when ('FF') {
        my $str = pack ('H*', $rest);
        $str =~ s/\n/%/g;
        print "   TEXT(FF): $str\n";
      }
      when ('44') {
        my $SID = shift @data;
        if ($SID eq 'FF') {
          $rest = join '', @data;
          my $str = pack ('H*', $rest);
          $str =~ s/\n/%/g;
          print "   TEXT(44):  $str\n";
        } else {
          print "    -skip unknown subcmd $MID/$SID $rest\n" if $DEBUG > 0;
        }
      }
      default {
        print "    -skip unknown cmd $MID $rest\n" if $DEBUG > 1;
      }
    }    
  } else {
    die "unknown format for line: $_";
  }
  #die;	# FIXME - test just first line
}
