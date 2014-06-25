    my $num = 11.833496;
    
        print join(" ", map { sprintf "0x%02x", $_ } 
                            unpack("C*", pack "d", $num)), "\n";
                            