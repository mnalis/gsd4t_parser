#!/usr/bin/perl -w
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-22
# parse .gp2 container having new GSD4t binary data (double-CRC one) and run checks on it
#
# Usage: ./parse_strace.pl | ./parse_newfmt.pl
#
use strict;
use autodie;

my $DEBUG = 9;

# format is like:
# 21/06/2014 00:02:23.287 (0)  A0 A2 00 03 E4 00 9F 00 14 04 5B 8E 02 03 01 43 03 71 00 00 00 00 00 00 00 00 00 00 00 00 00 F7 C9 B0 B3
#
# A0 A2 -- lead-in
# 00    -- always zero?
# 03E4  -- sequence1
# 009F  -- sequence2
# 0014  -- length of payload (length of full packet minus 0xf [full size of all headers]
# 045B  -- CRC16 (modbus) of headers
# 8E 02 03 01 43 03 71 00 00 00 00 00 00 00 00 00 00 00 00 00 -- actual payload (FIXME - what is in it?)
# F7 C9 -- CRC16 (modbus) of payload
# B0 B3 -- lead-out

my $last_seq1 = undef;
my $last_seq2 = undef;

while (<>) {
  if (m{^(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2})(\.\d{3}) \(0\) A0 A2 ([A-F0-9 ]+) B0 B3\s*}) {
    print "raw: $_" if $DEBUG > 8;
    next if /^\s*$/;	# skip empty lines
    next if /^\s*#/;	# skip comment lines

    my $date = $1; my $time = $2; my $msec=$3; 
    my @data = split ' ', $4;

#### byte 0 (always 00) ####
    my $p_lead_zero = shift @data; 
    if ($p_lead_zero ne '00') { die "leading zero not 00 but $p_lead_zero in $_" }
    print "  lead 00 -- OK\n" if $DEBUG > 7;

#### byte 1-2 (sequence1) ####
    my $p_seq1 = (shift @data) . (shift @data);
    my $seq1 = hex($p_seq1);
    if (defined $last_seq1) {
        # FIXME: allow seq1 to stay the same if we're null packet?
        # FIXME: allow wraparound
        if ($seq1 != $last_seq1 + 1) { die "last seq1 was $last_seq2, didn't expect $seq1 in $_" }	
        print "  seq1 $last_seq1 + 1 = $seq1 -- OK\n" if $DEBUG > 7;
    }
    $last_seq1 = $seq1;
    
    
#### byte 3-4 (sequence2) ####
    my $p_seq2 = (shift @data) . (shift @data);	#FIXME verify it is same or goes by +1
    my $seq2 = hex($p_seq2);
    if (defined $last_seq2) {
        # FIXME: allow wraparound
        if (($seq2 != $last_seq2 + 1) and ($seq2 != $last_seq2)) { die "last seq2 was $last_seq2, didn't expect $seq2 in $_" }	
        print "  seq2 $last_seq2 + 0/1 = $seq2 -- OK\n" if $DEBUG > 7;
    }
    $last_seq2 = $seq2;


#### byte 5-6 (payload length) ####
    my $p_length = (shift @data) . (shift @data);	# FIXME verify after length is lead-out
    my $length = hex($p_length);
    print "  packet length = 0x$p_length ($length)\n" if $DEBUG > 7;
        
#### byte 7-8 (header CRC-16) ####
    my $p_crc_head = (shift @data) . (shift @data);	# FIXME verify checksum
    my $crc_head = hex($p_crc_head);
    print "  header CRC16 = 0x$p_crc_head ($crc_head)\n" if $DEBUG > 7;

#### byte 9-xxx (actual payload) ####
    my $p_payload = '';	# FIXME extract $length amount of bytes
    print "  payload ==> $p_payload\n" if $DEBUG > 7;
    
#### byte xxx+1 and xxx+1 (payload CRC16) ####
    my $p_crc_payload = (shift @data) . (shift @data);	# FIXME verify checksum (also test if we get 'FFFF' on null-packet)
    my $crc_payload = hex($p_crc_payload);
    print "  payload CRC16 = 0x$p_crc_payload ($crc_payload)\n" if $DEBUG > 7;


    # FIXME verify rest of the packet is empty    

    print "  $time $p_payload\n" if $DEBUG > 3;

  } else {
    die "unknown format for line: $_";
  }
  die;	# FIXME - test just first line
}
