package FS::part_event::Condition::cust_bill_pkg_freq_over;

use strict;
use FS::Record qw(qsearch);
use FS::part_event;
use FS::cust_event;
use List::MoreUtils qw/any/;

use base qw( FS::part_event::Condition );

sub description { 
    'Invoice package freq is over a specified amount'; 
}

sub eventtable_hashref {
    {
        'cust_main' =>  0,
        'cust_bill' =>  1,
        'cust_pkg'  =>  0,
    };
}

sub option_fields {
    (
        freq => { 
            label   =>  'Package frequency',
            type    =>  'freq',
            value   =>  '1m',
        },
                
    );
}

sub condition {
    my ($self, $cust_bill, %opt) = @_;

    my $freq = parse_freq($self->option('freq'));
    return any { 
        # part_pkg,freq is measured in months (30 * 86400)
        ($_->part_pkg->freq * 2592000) >= $freq
    } $cust_bill->cust_bill_pkg;
}


sub parse_freq {
    my $freq = shift;

    my ($qty, $units) = $freq =~ m/^(\d+)([dmy])$/;
    
    my $seconds = 0;
    die "freq must contain positive integer amount" unless $qty;
    if ($units eq 'd') {
        $seconds = $qty * 86400;
    }
    elsif ($units eq 'm') {
        $seconds = $qty * 86400 * 30;
    }
    elsif ($units eq 'h') {
        $seconds = $qty * 3600;
    }
    else {
        die "Unknown freq unit type";
    }

    return $seconds;
}


1;
