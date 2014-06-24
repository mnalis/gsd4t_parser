#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-24
# parse decapsulated GSD4t .gp2 container format data and interprets it for human use
#
# Usage: ./strace_to_gp2.pl data/strace4/strace.log.3491 | ./enc4t_gp2_to_raw4t_gp2.pl | ./raw4t_gp2_to_human.pl
#
use strict;
use autodie;
use feature "switch";
use feature "say";

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

# returns n-byte value
sub get_byte($) {
    my ($count) = @_;
    my $ret = '';
    print "   reading $count byte-value: 0x" if $DEBUG > 6;
    while ($count--) { $ret .= shift @data }
    say "$ret" if $DEBUG > 6;
    return $ret;
}

# returns variable-length variable
sub get_varvar() {
    my $size = get_byte(1);
    print "   variable-length variable follows: 0x$size" if $DEBUG > 7;
    return get_byte(1) if ($size eq '20');
    return get_byte(2) if ($size eq '40');
    return get_byte(3) if ($size eq '60');
    die "unknown length variable of 0x$size -- $_";
}

######### MAIN ##########
while (<>) {
  next if /^\s*$/;	# skip empty lines
  next if /^\s*#/;	# skip comment lines
  if (m{^(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2})(\.\d{3}) \(0\) E1 0A ([A-F0-9 ]+)\s*}) {
    print "raw: $_" if $DEBUG > 8;
    my $date = $1; my $time = $2; my $msec=$3; 
    @data = split ' ', $4;
    my $CMD = shift @data;
    my $SUB = shift @data;
    my $expected_len = hex(shift @data);
    my $rest = join '', @data;
    
    my $real_len = 3+ scalar @data;		# "expected_len" includes CMD, SUB and expected_len
    if ($real_len != $expected_len) {
        warn "WARNING: skipping due to invalid length - found $real_len, expected $expected_len: $_";	
        # FIXME - sometimes length is not what it seems?
        next;
    }
    
    
    
    say "  $time $CMD $SUB ($expected_len) $rest" if $DEBUG > 3;
    
    print "$time$msec ";

    given ("$CMD$SUB") {
      when ('2D03') {
#      E1 0A 
#      2D 03 
#      13 40 02 58 05 00 19 20 29 60 01 7A C9 1E 00 20 F8   
          my $label = hex get_varvar();
          my $new = hex get_byte(1);
          my $type = hex get_byte(1);
          my $sv = hex get_byte(1);
          my $ch = hex get_byte(1);
          my $D = hex get_varvar();
          my $C = hex get_byte(1);
          my $c2 = hex get_byte(1);
          my $c3 = hex get_varvar();
          say "parsed 0x$CMD$SUB: $label ACQ: New$new type$type sv$sv ch$ch D:$D C:$C $c2 $c3";
          # FIXME -- maybe we always need to be get_varvar() ? and then if value is literal "40" for example, we would get "20 40" instead (20=1byte, 40=value);
      }
      when ('2D0B') {
          say "FIXME - parse 2D0B";
      }
      when ('3D04') {
          my $noise = hex get_varvar();
          my $n2 = hex get_varvar();
          my $freq = hex get_varvar();
          my $gain = hex get_byte(1);
          say "parsed 0x$CMD$SUB: AGC: noise $noise $n2 freq $freq gain $gain";
      }

      when ('4E0B') {
          my $label = hex get_varvar();
          my $sv = hex get_byte(1);
          my $ch = hex get_byte(1);
          my $cno= hex get_varvar();
          my $sync = hex get_byte(1);
          my $val = hex get_byte(1);
          my $frq = hex get_varvar();
          my $rest = get_byte(6);
          say "parsed 0x$CMD$SUB: $label TRACK: StartTrack sv$sv ch $ch cno$cno sync$sync val$val frq$frq -- FIXME rest: $rest";
      }

      default {
        say "skip unknown CMD 0x$CMD SUB 0x$SUB $rest" if $DEBUG > 0;
        next;
      }
    }
    
    # if we parsed packet, there should be NO data remaining...
    if (@data) {
      die "finished decoding packet, but data still remains: @data";
    }    
  } else {
    warn "# WARNING: unknown format for line (maybe not E1 0A - FIXME): $_";
  }
}
