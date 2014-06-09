package FS::part_export::hal_event_queue;

use strict;
use vars qw(%options %info);
use Tie::IxHash;
use base qw(FS::part_export);

use FS::UID qw/dbh/;

tie my %options, 'Tie::IxHash',
    target      =>  {
        label   =>  "Target label (e.g. 'HP' for Hosting Platform)",
        default =>  'HP',
    },
;

%info = (
    'svc'       =>  'svc_external',
    'desc'      =>  'Export for HAL and other hosting platform service management',
    'options'   =>  \%options,
    'nodomain'  =>  'Y',
    'notes'     =>  <<'END'
Notes about this HAL event queue export.
END
);

sub rebless { shift; }

sub _export_insert {
    my ($self, $svc) = (shift, shift);

    my $target = $self->option('target');
    new_event_queue_record($svc, 'insert', $target);
}

sub _export_delete {
    my ($self, $svc) = (shift, shift);

    my $target = $self->option('target');
    new_event_queue_record($svc, 'delete', $target);
}

sub _export_replace {
    my ($self, $svc) = (shift, shift);

    my $target = $self->option('target');
    new_event_queue_record($svc, 'replace', $target);
}

sub _export_suspend {
    my ($self, $svc) = (shift, shift);

    my $target = $self->option('target');
    new_event_queue_record($svc, 'suspend', $target);
}

sub _export_unsuspend {
    my ($self, $svc) = (shift, shift);

    my $target = $self->option('target');
    new_event_queue_record($svc, 'unsuspend', $target);
}

sub new_event_queue_record {
    my $svc = shift;
    my $action = shift;
    my $target = shift;

    my $dbh = FS::UID::dbh;
    my $sql = qq{
        INSERT INTO event_queue
            (pkgnum, svcnum, action, target, agentnum)
            VALUES (?, ?, 
		(SELECT id FROM event_queue_action WHERE name = ?), 
		(SELECT id FROM event_queue_target WHERE name = ?), ?)
    };

    my $rv = $dbh->do(
        $sql,
        {},
        $svc->cust_svc->cust_pkg->pkgnum,
        $svc->cust_svc->svcnum,
        $action,
        $target,
        $svc->cust_svc->cust_pkg->cust_main->agentnum,
    );

    warn "Could not insert event_queue record: ", $dbh->errstr
        unless $rv;
}

1;
