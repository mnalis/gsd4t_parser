#!/usr/bin/perl
# test to find out which params are for crc16-modbus
# see http://www.lammertbies.nl/comm/info/crc-calculation.html
# by Matija Nalis <mnalis-android@voyager.hr> GPLv3+, started 2014-06-22

 # OO style
 use Digest::CRC;

# $ctx = Digest::CRC->new(type=>"crc16");
# $ctx = Digest::CRC->new(width=>16, init=>0x2345, xorout=>0x0000,
#                         refout=>1, poly=>0x8005, refin=>1, cont=>1);


foreach my $init (0x0000, 0xffff) {
  foreach my $xorout  (0x0000, 0xffff) {
    foreach my $poly (0x8005, 0xA001) {
     foreach my $refout (0,1) {
       foreach my $refin (0,1) {
         foreach my $cont (0,1) {
           my $ctx = Digest::CRC->new(width=>16, init=> $init, xorout=>$xorout,
                                   refout=>$refout, poly=>$poly, refin=>$refin, cont=>$cont);

           $ctx->add("123456789");
           $digest = $ctx->hexdigest;
           print "digest (init=$init, xorout=$xorout, poly=$poly, refout=$refout, refin=$refin, cont=$cont  ==> 0x$digest\n";
         }
       }
     }
   }
 }
}