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
# 045B  -- CRC16 (modbus) of headers (OK!)
# 8E 02 03 01 43 03 71 00 00 00 00 00 00 00 00 00 00 00 00 00 -- actual payload (FIXME - what is in it?)
# F7 C9 -- CRC16 (modbus) of payload (OK!)
# B0 B3 -- lead-out

while (<>) {
  if (m{^(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2})(\.\d{3}) \(0\) A0 A2 ([A-F0-9 ]+) B0 B3\s*}) {
    print "raw: $_" if $DEBUG > 8;
    my $date = $1; my $time = $2; my $msec=$3; 
    my @data = split ' ', $4;

    my $lead_zero = shift @data; 
    if ($lead_zero ne '00') { die "leading zero not 00 but $lead_zero in $_" }

    my $seq1 = (shift @data) . (shift @data);	#FIXME verify it goes by +1
    my $seq2 = (shift @data) . (shift @data);	#FIXME verify it is same or goes by +1
    my $payload_length = (shift @data) . (shift @data);	# FIXME verify after length is lead-out
    my $crc_head = (shift @data) . (shift @data);	# FIXME verify checksum
    my $payload = '';	# FIXME extract $length amount of bytes
    my $crc_payload = (shift @data) . (shift @data);	# FIXME verify checksum
    # FIXME verify rest of the packet is empty    

    print "  $time $payload\n" if $DEBUG > 3;

  } else {
    die "unknown format for line: $_";
  }
  die;	# FIXME - test just first line
}
