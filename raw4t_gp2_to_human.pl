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

my $DEBUG = 3;
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
sub get_var() {
    my $size = get_byte(1);
    print "   possible variable-length variable follows: 0x$size" if $DEBUG > 7;
    return get_byte(1) if ($size eq '20');
    return get_byte(2) if ($size eq '40');
    return get_byte(3) if ($size eq '60');
    return get_byte(4) if ($size eq '80');
    die "unknown length variable of 0x$size -- $_" if ($size eq 'A0') or ($size eq 'C0') or ($size eq 'E0') ;	# FIXME - maybe those are special too, maybe not. die for now so we can check...
    return $size;	# if no special prefix for size, then it is our one-byte value!
}

# like hex(), but autodetect signed values
sub signhex($) {
    my ($h) = @_;
    my $ret = hex($h);
    $ret = unpack('l', pack('L', $ret)) if $h =~ /^FFFF....$/;	# FIXME: support any 32-bit? other sizes too?
    return $ret;
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
          my $label = hex get_var();
          my $new = hex get_var();
          my $type = hex get_var();
          my $sv = hex get_var();
          my $ch = hex get_var();
          my $D = hex get_var();
          my $C = signhex get_var();
          my $c2 = hex get_var();
          my $c3 = hex get_var();
          say "parsed 0x$CMD$SUB: $label ACQ: New$new type$type sv$sv ch$ch D:$D C:$C $c2 $c3";
      }
      when ('2D0B') {
          say "FIXME - parse 2D0B";
      }
      when ('3D04') {
          my $noise = hex get_var();
          my $n2 = hex get_var();
          my $freq = hex get_var();
          my $gain = hex get_var();
          say "parsed 0x$CMD$SUB: AGC: noise $noise $n2 freq $freq gain $gain";
      }

      when ('4E0B') {
          my $label = hex get_var();
          my $sv = hex get_var();
          my $ch = hex get_var();
          my $cno= hex get_var();
          my $sync = hex get_var();
          my $val = hex get_var();
          my $frq = hex get_var();
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
