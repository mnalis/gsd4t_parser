#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-24
# parse decapsulated GSD4t .gp2 container format data and interprets it for human use
#
# Usage: ./strace_to_gp2.pl data/strace4/strace.log.3491 | ./enc4t_gp2_to_raw4t_gp2.pl | ./raw4t_gp2_to_human.pl
#
use strict;
use autodie;
use feature "switch";

my $DEBUG = 2;
$| = 1;

# format is like:
# 00/00/0006 16:21:36.400 (0) E1 0A 2D 03 12 40 08 34 05 00 0E 1E 60 01 81 C7 00 00 20 F8 	#  seq1=0070 seq2=0007 len=0014
# E1 0A -- lead-in (although there seems to be others, like E1 09, 84, 8E etc... find them out later)
# 2D -- command/MID ("ACQ:")
# 03 -- subommand/SID ("New")
# 12 -- lenght of packet (ignoring E1 0A lead-in)
# 40....F8 -- rest of payload
# #comments

my @data=();

# returns 8-bit value
sub get_var8() {
    return shift @data;
}

while (<>) {
  next if /^\s*$/;	# skip empty lines
  next if /^\s*#/;	# skip comment lines
  if (m{^(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2})(\.\d{3}) \(0\) E1 0A ([A-F0-9 ]+)\s*}) {
    print "raw: $_" if $DEBUG > 8;
    my $date = $1; my $time = $2; my $msec=$3; 
    @data = split ' ', $4;
    my $CMD = shift @data;
    my $SUB = shift @data;
    my $length = hex(shift @data);
    my $rest = join '', @data;
    
    print "  $time $CMD $SUB ($length) $rest\n" if $DEBUG > 3;
    
    print "$time$msec ";

    given ("$CMD$SUB") {
      when ('2D03') {
          print "FIXME - parse 2D03\n";
      }

      
      default {
        print "skip unknown CMD 0x$CMD SUB 0x$SUB $rest\n" if $DEBUG > 0;
      }
    }    
  } else {
    warn "# WARNING: unknown format for line (maybe not E1 0A - FIXME): $_";
  }
}
