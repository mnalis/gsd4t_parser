use feature 'say';
    my $num = 11.833496;
    
    print "num=$num";
        print join(" ", map { sprintf "%02x", $_ } 
                            unpack("C*", pack "d", $num)), "\n";
                            
                            
my @hex = qw(40 27 AA C0 00 00 00 00);
my @rev = reverse @hex;
say "hex=@hex, rev=@rev";

my $packed =  pack "H*", join('', @rev);
#say "packed = $packed";
say "decoded= " . unpack "d*", $packed;