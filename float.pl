use feature 'say';
    my $num = 43.724884;
    
    say "num=$num";
    say join(" ", map { sprintf "%02x", $_ } 
                            unpack("C*", pack "f", $num));
                            
                            
my @hex = qw(3E 2F BE 91);
my @rev = reverse @hex;
say "hex=@hex, rev=@rev";

my $packed =  pack "H*", join('', @rev);
#say "packed = $packed";
say "decoded= " . unpack "f*", $packed;


say "trying all combinations";

use Algorithm::Permute;

Algorithm::Permute::permute {
    my $packed =  pack "H*", join('', @hex);
    my $float = unpack "f*", $packed;
    my $double = unpack "d*", $packed;
    say "  next permutation: @hex -- float=$float\tdouble=$double";
} @hex;
