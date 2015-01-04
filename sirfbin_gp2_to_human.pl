#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-21
# parse SLCLog.gp2 created by GSD4t on Samsung Galaxy S2 running CyanogenMod9
#
# Usage: ./sirfbin_gp2_to_human.pl data/2/SLCLog.gp2
#
use strict;
use autodie;
use feature "switch";
use feature "say";

my $DEBUG = 2;
$| = 1;

my @data;
my $MID;

# returns n-byte value
sub get_byte($) {
    my ($count) = @_;
    my $ret = '';
    print "   reading $count byte-value: 0x" if $DEBUG > 6;
    while ($count--) {
        my $h = shift @data;
        if (!defined $h) { die "not enough data in packet, at least " . ($count+1) . " missing -- read so far: $ret" }
        $ret .= $h;
    }
    say "$ret" if $DEBUG > 6;
    return $ret;
}


#from gpsd(1) source
#/* big-endian access */
#define getbes16(buf, off)      ((int16_t)(((uint16_t)getub(buf, (off)) << 8) | (uint16_t)getub(buf, (off)+1)))
#define getbeu16(buf, off)      ((uint16_t)(((uint16_t)getub(buf, (off)) << 8) | (uint16_t)getub(buf, (off)+1)))
#define getbes32(buf, off)      ((int32_t)(((uint16_t)getbeu16(buf, (off)) << 16) | getbeu16(buf, (off)+2)))
#define getbeu32(buf, off)      ((uint32_t)(((uint16_t)getbeu16(buf, (off)) << 16) | getbeu16(buf, (off)+2)))
#define getbes64(buf, off)      ((int64_t)(((uint64_t)getbeu32(buf, (off)) << 32) | getbeu32(buf, (off)+4)))
#define getbeu64(buf, off)      ((uint64_t)(((uint64_t)getbeu32(buf, (off)) << 32) | getbeu32(buf, (off)+4)))

# returns big-endian unsigned integer 16-bits
sub getbeu16() {
    return hex get_byte(2);
}
# returns big-endian unsigned integer 16-bits
sub getbes16() {
    return unpack('s', pack('S', getbeu16));
}

# returns big-endian unsigned integer 32-bits
sub getbeu32() {
    return hex get_byte(4);
}
# returns big-endian signed integer 32-bits
sub getbes32() {
    return unpack('l', pack('L', getbeu32));
}

# returns unsigned integer 8-its
sub getub() {
    return hex get_byte(1);
}
######### MAIN ##########

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
    @data = split ' ', $4;
    my $pkt_length = hex((shift @data) . (shift @data));
    $MID = shift @data;
    
    my $checksum = pop @data; $checksum = hex((pop @data) . $checksum);
    my $verify = hex($MID); 
    foreach my $x (@data) { $verify += hex($x); }
    $verify = $verify & 0x7FFF;	# 15 bit only? without it we sometimes die on mismatch like 07F5 / 87F5
    
    my $rest = join '', @data;
    if ((length "$MID$rest") != $pkt_length * 2) { die "invalid packet length $pkt_length != " . (length "$MID$rest")/2 . " in $_" }
    $rest = join ' ', @data;	# more readable this way

    print "  packet $time (len=$pkt_length) $MID $rest (cksum $checksum/$verify)\n" if $DEBUG > 6;
    if ($checksum != $verify) { die "invalid checksum $checksum != $verify for $_" }
    
    print "  $time $MID $rest\n" if $DEBUG > 3;
    
    print "$time$msec ";

    given ($MID) {
      when ('FF') {
        $rest = join '', @data;
        my $str = pack ('H*', $rest);
        $str =~ s/\n/%/g;
        print "DEBUG TEXT(FF): $str\n";
        @data = ();
      }

      when ('E1') {
        $rest = join '', @data;
        my $str = pack ('H*', $rest);
        $str =~ s/(.)/chr(ord($1)^0xff)/ge;	# XOR 0xFF
        $str =~ s/^\xFF//;			# remove leading 0xFF if exists
        $str =~ s/\n/%/g;
        print "DEV TEXT(E1): $str\n";
        @data = ();
      }
      
      when ('44') {
        my $SID = shift @data;
        if ($SID eq 'FF') {
          $rest = join '', @data;
          my $str = pack ('H*', $rest);
          $str =~ s/\n/%/g;
          print "DEBUG TEXT(44/FF):  $str\n";
        } elsif ($SID eq 'E1') {
          $rest = join '', @data;
          my $str = pack ('H*', $rest);
          $str =~ s/(.)/chr(ord($1)^0xff)/ge;	# XOR 0xFF
          $str =~ s/^\xFF//;			# remove leading 0xFF if exists
          $str =~ s/\n/%/g;
          print "DEV TEXT(44/E1): $str\n";
        } else {
          $rest = join ' ', @data;
          say "MID 0x$MID - skip unknown SID 0x$SID - $rest";
        }
        @data = ();
      }

      
      when ('02') {
          say "GPSD knows MID 0x$MID --  Measure Navigation Data Out MID 2 -- hex $rest";
          printf "  GPS location fix found!\n";
          my ($x, $y, $z) = (getbes32, getbes32, getbes32);
          printf "   x=%d y=%d z=%d\n", $x, $y, $z;
          eval {
            require Geo::ECEF;
            my $obj=Geo::ECEF->new(); #WGS84 is the default
            my ($lat, $lon, $hae)=$obj->geodetic($x, $y, $z);
            printf "     (lat=$lat, lon=$lon, HAE=$hae -- FIXME ECEF calc precision?)\n";
          };
          say "     (WARNING: No Geo::ECEF found, not calculating WGS84)" if $@;
          printf "   xv=%f yv=%f zv=%f\n", getbes16 / 8, getbes16 / 8, getbes16 / 8;
          printf "   mode1=0x%x HDOP=%f mode2=0x%x\n", getub, getub / 5, getub;
          my $week=getbes16; my $TOW = getbeu32 / 100;
          printf "   GPS week=%d TOW=%f\n", $week, $TOW;
          my $gpstime = 315964800 + ($week + 1*1024)*60*60*24*7 + $TOW;
          printf "     (time=$gpstime ==> %s -- FIXME: kludge 1 overflow, no leap seconds calc)\n", localtime($gpstime) . "";
          printf "   SVs in fix=%d, CH1-12 PRN: %d %d %d %d %d %d %d %d %d %d %d %d\n", getub, getub, getub, getub, getub, getub, getub, getub, getub, getub, getub, getub, getub;
      }

      when ('04') {
          say "GPSD knows MID 0x$MID --  Measured tracker data out MID 4 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('05') {
          say "GPSD knows MID 0x$MID --  (unused) Raw Tracker Data Out MID 5 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('06') {
          say "GPSD knows MID 0x$MID --  Software Version String MID 6 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('07') {
          say "GPSD knows MID 0x$MID --  (unused) Clock Status Data MID 7 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('08') {
          say "GPSD knows MID 0x$MID --  subframe data MID 8 (extract leap-second from this) -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('09') {
          say "GPSD knows MID 0x$MID --  (unused debug) CPU Throughput MID 9 -- hex $rest";
          printf "  SiRF: THR 0x09: SegStatMax=%.3f, SegStatLat=%3.f, AveTrkTime=%.3f, Last MS=%u\n",
            getbeu16 / 186, getbeu16 / 186, getbeu16 / 186, getbeu16;
      }

      when ('0A') {
          say "GPSD knows MID 0x$MID --  Error ID Data MID 10 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('0B') {
          say "GPSD knows MID 0x$MID --  Command Acknowledgement MID 11 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('0C') {
          say "GPSD knows MID 0x$MID --  (unused debug) Command NAcknowledgement MID 12 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('0D') {
          say "GPSD knows MID 0x$MID --  (unused debug) Visible List MID 13 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('0E') {
          say "GPSD knows MID 0x$MID --  (unused) Almanac Data MID 14 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('0F') {
          say "GPSD knows MID 0x$MID --  (unused) Ephemeris Data MID 15 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('11') {
          say "GPSD knows MID 0x$MID --  (unused) Differential Corrections MID 17 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('12') {
          say "GPSD knows MID 0x$MID --  (unused debug) OK To Send MID 18 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('13') {
          say "GPSD knows MID 0x$MID --  Navigation Parameters MID 19 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('1B') {
          say "GPSD knows MID 0x$MID --  DGPS status MID 27 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('1C') {
          say "GPSD knows MID 0x$MID --  (unused debug) (len should be 0x38) Navigation Library Measurement Data MID 28 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('1D') {
          say "GPSD knows MID 0x$MID --  (unused) Navigation Library DGPS Data MID 29 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('1E') {
          say "GPSD knows MID 0x$MID --  (unused) Navigation Library SV State Data MID 30 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('1F') {
          say "GPSD knows MID 0x$MID --  (unused) Navigation Library Initialization Data MID 31 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('29') {
          say "GPSD knows MID 0x$MID --  (unused) Geodetic Navigation Data MID 41 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('32') {
          say "GPSD knows MID 0x$MID --  (unused) SBAS corrections MID 50 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('33') {
          say "MID 0x$MID Tracker Load Status Report (UNUSED) -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('34') {
          say "GPSD knows MID 0x$MID --  PPS Time MID 52 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('38') {
          say "GPSD knows MID 0x$MID --  EE Output MID 56 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('40') {
          say "GPSD knows MID 0x$MID --  Nav Library MID 64 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('45') {
          my $SID = shift @data;
          $rest = join ' ', @data;
          
          if ($SID eq '01') {
              say "guess MID 0x$MID SID 0x$SID -- related to DetailedLog.txt OSP_POSITION_RESPONSE ? -- hex $rest";
          } elsif ($SID eq '02') {
              say "guess MID 0x$MID SID 0x$SID -- related to DetailedLog.txt OSP_MEASURE_RESPONSE ? -- hex $rest";
          } else {
              say "MID 0x$MID - skip unknown SID 0x$SID - $rest";
          }
          @data = ();	# FIXME DELME
      }

      when ('47') {
          say "GPSD knows MID 0x$MID --  (unused) Hardware Config MID 71 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('5C') {
          say "GPSD knows MID 0x$MID --  (unused) CW Controller Output MID 92 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('5D') {
          say "GPSD knows MID 0x$MID --  (unused) TCXO Output MID 93 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('62') {
          say "GPSD knows MID 0x$MID --  u-blox Extended Measured Navigation Data MID 98 -- hex $rest";
          @data = ();	# FIXME DELME
      }

      when ('80') {
          say "GPSD knows MID 0x$MID --  (unused) Initialize Data Source MID 128 -- hex $rest";
          @data = ();	# FIXME DELME
      }
      
      
      default {
        say "skip unknown MID 0x$MID -- hex $rest" if $DEBUG > 0;
        @data = ();
      }
    }
    $rest = join '', @data;
    die " not parsed correctly -- bytes remaining: hex $rest\n"  if $rest;
  } else {
    die "unknown format for line: $_";
  }
}
