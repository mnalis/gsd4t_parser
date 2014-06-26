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

my $packet;	# whole packet
my @data=();	# split packet
my $CMD;	# command/MID equivalent
my $SUB;	# subcommand/SID equivalent
my $expected_len;	# expected total length of packet

# returns n-byte value
sub get_byte($) {
    my ($count) = @_;
    my $ret = '';
    print "   reading $count byte-value: 0x" if $DEBUG > 6;
    while ($count--) {
        my $h = shift @data;
        if (!defined $h) { die "not enough data in packet, at least " . ($count+1) . " missing -- read so far: $ret. Full packet data: $packet" }
        $ret .= $h;
    }
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

# fills vars passed as reference with hex values of get_var()
sub get_hexvars {
    foreach my $ref (@_) {
        $ref = hex get_var();
    }
}

# like hex(), but autodetect signed values
sub signhex($) {
    my ($h) = @_;
    my $ret = hex($h);
    $ret = unpack('l', pack('L', $ret)) if $h =~ /^FFFF....$/;	# FIXME: support any 32-bit? other sizes too?
    return $ret;
}

# returns floating point number from packet (encoded as 4-byte)
sub get_float() {
    sub float($) {	# returns floating point representation
        my ($h) = @_;
        return sprintf("%.2f", unpack "f*", pack "N*", unpack "V*", pack "H*", $h);	# convert (assumed) 4 hex bytes in IEEE-754 floating point. beware of the endian issues!
    }
    return float get_byte(4);
}

# returns double-precision floating point number from packet (encoded as 8-byte)
sub get_double() {
    sub double($) {	# returns double precision floating point representation
        my ($h) = @_;
        my @h2 = reverse map "$_", $h =~ /(..)/g;
        return sprintf("%.9f", unpack "d*", pack "H*", join('',@h2));	# convert (assumed) 8 hex bytes in IEEE-754 double precision floating point. beware of the endian issues!
    }
    return double get_byte(8);
}

# given format string, returns debug text describing packet. 
# uses sprintf(3)-alike templates:
#   %u is variable length unsigned decimal
#   %d is variable length signed decimal
#   %x is variable length unsigned hexadecimal
#   %f is 4-byte float
#   %g is 8-byte double
#   %c is 1-byte char
#   %s is variable length (AND 0-terminated) array of chars (C string prefixed with length)
#   %X (special) is 1-byte hex value
#   %0 (special) - read 1-byte value and discard it, not printing anything
sub parsed($) {
    # FIXME - maybe we should just use sprintf() instead trying to reinvent it badly?
    sub parse_one($) {		# fetches from packet and parses one format variable
        my ($format) = @_;
        say "     parse_one: %$format" if $DEBUG > 9;
        given ($format) {
            when ('u') { return hex get_var() }
            when ('d') { return signhex get_var() }
            when ('x') { return get_var() }
            when ('f') { return get_float() }
            when ('g') { return get_double() }
            when ('c') { return chr hex get_var() }
            when ('s') { 
                my $size = hex get_byte(1);
                my $r=''; 
                while (my $c=hex get_byte(1)) {
                    $r .= chr $c;
                    $size--; 
                }; 
                if ($size != 0) { die "$size bytes remains in %s of '$r'" }
                return $r;
            }
            when ('X') { return get_byte(1) }
            when ('0') { get_byte(1); return '' }
            default { die "parse_one: unknown format char %$format" }
        }
    }
    my ($str) = @_;
    $str =~ s/%(.)/parse_one($1)/ge;
    if ($str =~ /%/) { die "unknown format parametar in $str" }
    return "parsed 0x$CMD$SUB: $str";
}

# parse unknown number of subpackets
sub parse_subpackets ($$) {
  my ($cmd_sub, $len_sub) = @_;
        
  my $str = '';
  while (@data) {
      my $sCMD = get_byte(1);
      my $sSUB = get_byte(1);
      my $sLEN = get_byte(1);
      if ("$sCMD$sSUB" ne $cmd_sub or $sLEN != $len_sub) { die "don't understand 0x1420 subpacket 0x$sCMD$sSUB($sLEN) -- should be 0x$cmd_sub($len_sub)" }
      my $sDATA = get_byte ($sLEN-3);	# sCMD+sSUB+sLEN have already been read
      
      foreach my $d (map "$_", $sDATA =~ /(..)/g) {
          $str .= hex($d) . "-";
      }
      chop $str; $str .= ' ';
      
      $expected_len += $sLEN;
  }
  chop $str;
  return $str;
}

######### MAIN ##########
while (<>) {
  next if /^\s*$/;	# skip empty lines
  next if /^\s*#/;	# skip comment lines
  if (m{^(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2})(\.\d{3}) \(0\) ([A-F0-9 ]*)\h*(\h+.*?)?$}) {
    print "raw: $_" if $DEBUG > 8;
    my $date = $1; my $time = $2; my $msec=$3; 
    $packet = $4;
    my $comments = $5;
    @data = split ' ', $packet;
    
    if (!@data) {
        say "$time$msec empty packet  $comments" if $DEBUG > 2;
        next;
    }
    my $LEAD_IN = get_byte(2);
    
    if ($LEAD_IN eq 'E10A' or $LEAD_IN eq 'E109' ) {	# FIXME indent properly
    $CMD = get_byte(1);
    $SUB = get_byte(1);
    $expected_len = hex get_byte(1);
    my $rest = join '', @data;
    
    my $real_len = 3+ scalar @data;		# "expected_len" includes CMD, SUB and expected_len
    
    say "  $time $LEAD_IN $CMD $SUB ($expected_len) $rest" if $DEBUG > 3;
    
    print "$time$msec ";

    given ("$CMD$SUB") {
      when ('1420') {
          print parsed "%u ChdevsA: ";
          say parse_subpackets('1422', 5);
      }

      when ('1421') {
          print parsed "%u ChdevsB: ";
          say parse_subpackets('1422', 5);
      }

      when ('1423') {
          print parsed "%u SSPa:%u: ";
          say parse_subpackets('1425', 6);
      }
          
      when ('1A00') {
          say parsed "%u SSS: Start. %x sssMode%u preposMode %u"; 
      }

      when ('1E04') {
          say parsed "%u SSS: Commanded l:%u h:%u new:%x";
      }

      when ('1E0B') {
          say parsed "%u ATX: Insample ADC select: %u"; 
      }

      when ('1E0D') {
          say parsed "%u ATX: Insample mode switch: Mode:%u Ins:%u status=0x%x"; 
      }

      when ('1E0F') {
          say parsed "%u ATX: Insample Switch Request: Evt:0x%x oldIns:%u newIns:%u"; 
      }

      when ('1F00') {
          say parsed "%u ATX Init: Seq:%u Mode:%u Ev:0x%x SVList:0x%x 0x%x SVs:%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u";
      }

      when ('1F01') {
          say parsed "%u ATX PP: Seq:%u Mode:%u Ev:0x%x A:%u SVList:0x%x 0x%x SVs:%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u";
      }

      when ('2208') {
          say parsed "%u ACQ: New%u type%u sv%u ch %u D:%u C:%d cno%u t %u ms %u bn %u";
      }

      when ('2D03') {
          say parsed "%u ACQ: New%u type%u sv%u ch%u D:%u C:%d %u %u";
      }
    
      when ('2D0B') {
          # FIXME is "%x" before "ms:"  ok? one byte, but we should get '0000'... huh
          say parsed "%u ACQ: %c%u sv%u ch%u CN0:%u D:%u  %u C:%f %f Th:%u %u Pk:%u %u %u %x ms:%u vo:%u bs:%u %u %u %u";
      }
    
      when ('3D04') {
          say parsed "AGC: noise %u %u freq %u gain %u";
      }

      when ('4E0B') {
          say parsed "%u TRACK: StartTrack sv%u ch%u cno%u sync%u val%u frq%u -- FIXME rest: %X %X %X %X %X %X";
      }
      when ('5400') {
          say parsed "%u BEP:SetTime(RTC) YY T:%g %u %u A:%u AC:%f Adj:%g dCB:%f";
      }


      when ('5413') {
          say parsed "CM:RtcGetPrecise: rtcCal:%g rtcDft:%g rtcTT:%g Dt:%g rtcCnt:%u rtcAcq:%u tUnc:%g towCal:%g tow:%g cd:%u";
      }
      
      when ('5426') {
          say parsed "%u CM:RtcEdgeAlign T:%u dRate:%u count:%u %u Acq:%u Wclk:%u dRtc:%g prevAcq:%u bepDrift:%g rtcDrift:%g";
      }
      
      when ('5493') {
          say parsed "%u CM:XO:Upd:tVal:%u wn:%u freq:%u freqEst:%u uTNEst:%u uMN:%u uMF:%u uTN:%u uTF:%u uAN:%u uAF:%u uN:%u uF:%u";
      }
      
      when ('5494') {
          say parsed "%u CM:XO:LastCal:%u freq:%u freqUnc:%u rD:%g rT:%g tr:%u uG:%u fHC:%u mD:%u";
      }
      
      when ('5495') {
          say parsed "%u CM:XoRampRateCheck:%u reset:%u rr:%u dTemp:%u dt:%u t:%u to:%u";
      }

      when ('69AB') {
          say parsed "%u ATX: Meas Send:%u %u %u %u %u %u %u %u";
      }

      
      #### FIXME: E109 uses much of the same infrastucture as E10A, so we keep it here, and hope for no same CMD/SUB pairs :) ####
      when ('5800') {
          if ($LEAD_IN ne 'E109') { die "0x$CMD$SUB should only be in E109, not $LEAD_IN" }
          say parsed "(guess) SiRF GPS SW Version: %s";
      }

      when ('5802') {
          if ($LEAD_IN ne 'E109') { die "0x$CMD$SUB should only be in E109, not $LEAD_IN" }
          say parsed "(guess) Compiler: %s";
      }
      when ('5803') {
          if ($LEAD_IN ne 'E109') { die "0x$CMD$SUB should only be in E109, not $LEAD_IN" }
          say parsed "(guess) ASIC %s 0x%x";
      }
      when ('5805') {
          if ($LEAD_IN ne 'E109') { die "0x$CMD$SUB should only be in E109, not $LEAD_IN" }
          say parsed "(guess) Config: RefClk: %u Hz ClkOffset: %u Hz Unc: %u ppb Lna: %s Baud: %u Backup LDO: %s";
      }
      when ('5804') { 
          if ($LEAD_IN ne 'E109') { die "0x$CMD$SUB should only be in E109, not $LEAD_IN" }
  	  say parsed "CPU Speed: %s    Cache: %s"; 
      }
      when ('5E09') { 
          if ($LEAD_IN ne 'E109') { die "0x$CMD$SUB should only be in E109, not $LEAD_IN" }
	  say parsed "%s"; 
      }
      when ('5700') {
          if ($LEAD_IN ne 'E109') { die "0x$CMD$SUB should only be in E109, not $LEAD_IN" }
          say parsed "%s"; 
      }
      #### FIXME: end E109 command block ####
      

      default {
        say "skip lead-in 0x$LEAD_IN unknown CMD 0x$CMD SUB 0x$SUB $rest" if $DEBUG > 0;
        #next; # FIXME DELME
        my $count=0;
        while (@data) {
            if ($data[0] =~ /^[ACE]0/) {	# this would die on get_var(). so  assume float (athough it might be double, too)
              my $unk_float = get_float();
              say "    unknown var$count (guess float?) = $unk_float";
            } else {		# guess normal byte
              my $unknown = get_var();
              my $unk_dec = hex($unknown);
              say "    unknown var$count = 0x$unknown ($unk_dec)"; 
            }
            $count++;
        }
        # die "FIXME this cmdcode" if "$CMD$SUB" eq '1F01';
        # die "FIXME please parse and add this command code $CMD $SUB";
        next;
      }
    }
    
    # if we parsed packet ccrrectly, there should be NO data remaining...
    if (@data) {
      die "finished decoding packet, but data still remains: @data";
    }    

    if ($real_len != $expected_len) {
        die "FATAL: invalid length - found $real_len, expected $expected_len: $_";	
    }
    
    } elsif ($LEAD_IN =~ /^81..$/) {	# FIXME indent properly
        say "$time$msec unknown empty-load LEAD-IN of 0x$LEAD_IN";
        if (@data) { die "finished decoding packet, but data still remains: @data" }
    } else {
        print "$time$msec currently unsupported LEAD-IN $LEAD_IN: $_";
        next;
    }

  } else {
    die "FATAL: unknown format for line: $_";
  }
}
