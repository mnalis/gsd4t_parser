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
  next if /^\s*$/;	# skip empty lines
  next if /^\s*#/;	# skip comment lines
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
    
    print "$time$msec ";

    given ($MID) {
      when ('FF') {
        my $str = pack ('H*', $rest);
        $str =~ s/\n/%/g;
        print "DEBUG TEXT(FF): $str\n";
      }
      
      when ('44') {
        my $SID = shift @data;
        if ($SID eq 'FF') {
          $rest = join '', @data;
          my $str = pack ('H*', $rest);
          $str =~ s/\n/%/g;
          print "DEV TEXT(44):  $str\n";
        } else {
          print "MID 0x$MID -skip unknown SID 0x$SID - $rest\n" if $DEBUG > 0;
        }
      }

      
      when ('02') {
          print "GPSD knows MID 0x$MID --  Measure Navigation Data Out MID 2\n";
      }

      when ('04') {
          print "GPSD knows MID 0x$MID --  Measured tracker data out MID 4\n";
      }

      when ('05') {
          print "GPSD knows MID 0x$MID --  (unused) Raw Tracker Data Out MID 5\n";
      }

      when ('06') {
          print "GPSD knows MID 0x$MID --  Software Version String MID 6\n";
      }

      when ('07') {
          print "GPSD knows MID 0x$MID --  (unused) Clock Status Data MID 7\n";
      }

      when ('08') {
          print "GPSD knows MID 0x$MID --  subframe data MID 8 (extract leap-second from this)";
      }

      when ('09') {
          print "GPSD knows MID 0x$MID --  (unused debug) CPU Throughput MID 9\n";
      }

      when ('0A') {
          print "GPSD knows MID 0x$MID --  Error ID Data MID 10\n";
      }

      when ('0B') {
          print "GPSD knows MID 0x$MID --  Command Acknowledgement MID 11\n";
      }

      when ('0C') {
          print "GPSD knows MID 0x$MID --  (unused debug) Command NAcknowledgement MID 12\n";
      }

      when ('0D') {
          print "GPSD knows MID 0x$MID --  (unused debug) Visible List MID 13\n";
      }

      when ('0E') {
          print "GPSD knows MID 0x$MID --  (unused) Almanac Data MID 14\n";
      }

      when ('0F') {
          print "GPSD knows MID 0x$MID --  (unused) Ephemeris Data MID 15\n";
      }

      when ('11') {
          print "GPSD knows MID 0x$MID --  (unused) Differential Corrections MID 17\n";
      }

      when ('12') {
          print "GPSD knows MID 0x$MID --  (unused debug) OK To Send MID 18\n";
      }

      when ('13') {
          print "GPSD knows MID 0x$MID --  Navigation Parameters MID 19\n";
      }

      when ('1B') {
          print "GPSD knows MID 0x$MID --  DGPS status MID 27\n";
      }

      when ('1C') {
          print "GPSD knows MID 0x$MID --  (unused debug) (len should be 0x38) Navigation Library Measurement Data MID 28\n";
      }

      when ('1D') {
          print "GPSD knows MID 0x$MID --  (unused) Navigation Library DGPS Data MID 29\n";
      }

      when ('1E') {
          print "GPSD knows MID 0x$MID --  (unused) Navigation Library SV State Data MID 30\n";
      }

      when ('1F') {
          print "GPSD knows MID 0x$MID --  (unused) Navigation Library Initialization Data MID 31\n";
      }

      when ('29') {
          print "GPSD knows MID 0x$MID --  (unused) Geodetic Navigation Data MID 41\n";
      }

      when ('32') {
          print "GPSD knows MID 0x$MID --  (unused) SBAS corrections MID 50\n";
      }

      when ('34') {
          print "GPSD knows MID 0x$MID --  PPS Time MID 52\n";
      }

      when ('38') {
          print "GPSD knows MID 0x$MID --  EE Output MID 56\n";
      }

      when ('40') {
          print "GPSD knows MID 0x$MID --  Nav Library MID 64\n";
      }

      when ('47') {
          print "GPSD knows MID 0x$MID --  (unused) Hardware Config MID 71\n";
      }

      when ('5C') {
          print "GPSD knows MID 0x$MID --  (unused) CW Controller Output MID 92\n";
      }

      when ('5D') {
          print "GPSD knows MID 0x$MID --  (unused) TCXO Output MID 93\n";
      }

      when ('62') {
          print "GPSD knows MID 0x$MID --  u-blox Extended Measured Navigation Data MID 98\n";
      }

      when ('80') {
          print "GPSD knows MID 0x$MID --  (unused) Initialize Data Source MID 128\n";
      }
      
      
      default {
        print "skip unknown MID 0x$MID $rest\n" if $DEBUG > 0;
      }
    }    
  } else {
    die "unknown format for line: $_";
  }
}
