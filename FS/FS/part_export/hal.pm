package FS::part_export::hal;

use strict;
use vars qw(%options %info);
use Tie::IxHash;
use base qw(FS::part_export);

use lib qw( /var/core_lib/lib );
use API::Client;

tie %options, 'Tie::IxHash',
    'result'  => { 
        label   => 'Result',
        type    => 'select',
        options => [ 'success', 'failure', 'exception' ],
        default => 'success',
    },
    'errormsg'=> { 
        label   => 'Error message',
        default => 'Test export',
    },
    'insert'  => { 
        label   => 'Insert',  
        type    => 'checkbox', 
        default => 1, 
    },
    'delete'  => { 
        label   => 'Delete', 
        type    => 'checkbox', 
        default => 1, 
    },
    'replace' => { 
        label   => 'Replace',
        type    => 'checkbox', 
        default => 1, 
    },
    'suspend' => { 
        label   => 'Suspend',
        type    => 'checkbox', 
        default => 1, 
    },
    'unsuspend'=>{ 
        label   => 'Unsuspend', 
        type    => 'checkbox', 
        default => 1, 
    },
;

%info = (
    'svc'     => [ qw(svc_acct) ],
    'desc'    => 'Real-time export to HAL',
    'options' => \%options,
    'notes'   => <<END,
<p>HAL export, for provisioning accounts via HAL.</p>
END
);

=head2 export_insert

This method sets up service for a new hosting account and associates it
with a customer.

For VPS/Dedicated, this involves doing a server_reserve and capturing the
hal_server_id.

=cut

sub export_insert {
    my $self = shift;
    my $svc_acct = shift;

    # HAL needs the following information to create a new server
    # - customer_uid 
    # - back_reference
    # - flavor_id
    # - image_group_id 	
    # - platform_id
    # 
    my $client = API::Client->new({ type => 'hal' });
    my $resp = $client->server_add({
        customer_uid    =>  $svc_acct->svcnum,
        back_reference  =>  $svc_acct->svcnum,
        flavor_id       =>  $flavor_id,
        image_group_id  =>  $image_group_id,
        platform_id     =>  $platform_id,
    });

    unless ($resp->data->{'success'}) {
        die "hal export_insert: " . $resp->error;
    }
    
    my $hal_server_id = $resp->data->{'id'};
    # Do something with this hal_server_id - store it somewhere
}

sub export_delete {
    my $self = shift;
    my $client = API::Client->new({ type => 'hal' });

    my $resp = $client->run_method( server_decom => {
        id  =>  $hal_server_id,
    });

    unless ( $resp->data->{'success'} ) {
        die "hal export_delete: " . $resp->error;
    }
}

sub export_suspend {
    my $self = shift;
    my $client = API::Client->new({ type => 'hal' });

    my $resp = $client->run_method( server_disable => {
        id  =>  $hal_server_id,
    });

    unless ( $resp->data->{'success'} ) {
        die "hal export_suspend: " . $resp->error;
    }
}

sub export_unsuspend {
    my $self = shift;
    my $client = API::Client->new({ type => 'hal' });

    my $resp = $client->run_method( server_restore => {
        id  =>  $hal_server_id,
    });

    unless ( $resp->data->{'success'} ) {
        die "hal export_unsuspend: " . $resp->error;
    }

}


1;
