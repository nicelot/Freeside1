package FS::svc_Common;
use base qw( FS::cust_main_Mixin FS::Record );

use strict;
use vars qw( $noexport_hack $DEBUG $me
             $overlimit_missing_cust_svc_nonfatal_kludge );
use Carp qw( cluck carp croak confess ); #specify cluck have to specify them all
use Scalar::Util qw( blessed );
use Lingua::EN::Inflect qw( PL_N );
use FS::Conf;
use FS::Record qw( qsearch qsearchs fields dbh );
use FS::cust_svc;
use FS::part_svc;
use FS::queue;
use FS::cust_main;
use FS::inventory_item;
use FS::inventory_class;
use FS::NetworkMonitoringSystem;

$me = '[FS::svc_Common]';
$DEBUG = 0;

$overlimit_missing_cust_svc_nonfatal_kludge = 0;

=head1 NAME

FS::svc_Common - Object method for all svc_ records

=head1 SYNOPSIS

package svc_myservice;
use base qw( FS::svc_Common );

=head1 DESCRIPTION

FS::svc_Common is intended as a base class for table-specific classes to
inherit from, i.e. FS::svc_acct.  FS::svc_Common inherits from FS::Record.

=head1 METHODS

=over 4

=item new

=cut

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self = {};
  bless ($self, $class);

  unless ( defined ( $self->table ) ) {
    $self->{'Table'} = shift;
    carp "warning: FS::Record::new called with table name ". $self->{'Table'};
  }
  
  #$self->{'Hash'} = shift;
  my $newhash = shift;
  $self->{'Hash'} = { map { $_ => $newhash->{$_} } qw(svcnum svcpart) };

  $self->setdefault( $self->_fieldhandlers )
    unless $self->svcnum;

  $self->{'Hash'}{$_} = $newhash->{$_}
    foreach grep { defined($newhash->{$_}) && length($newhash->{$_}) }
                 keys %$newhash;

  foreach my $field ( grep !defined($self->{'Hash'}{$_}), $self->fields ) { 
    $self->{'Hash'}{$field}='';
  }

  $self->_rebless if $self->can('_rebless');

  $self->{'modified'} = 0;

  $self->_cache($self->{'Hash'}, shift) if $self->can('_cache') && @_;

  $self;
}

#empty default
sub _fieldhandlers { {}; }

sub virtual_fields {

  # This restricts the fields based on part_svc_column and the svcpart of 
  # the service.  There are four possible cases:
  # 1.  svcpart passed as part of the svc_x hash.
  # 2.  svcpart fetched via cust_svc based on svcnum.
  # 3.  No svcnum or svcpart.  In this case, return ALL the fields with 
  #     dbtable eq $self->table.
  # 4.  Called via "fields('svc_acct')" or something similar.  In this case
  #     there is no $self object.

  my $self = shift;
  my $svcpart;
  my @vfields = $self->SUPER::virtual_fields;

  return @vfields unless (ref $self); # Case 4

  if ($self->svcpart) { # Case 1
    $svcpart = $self->svcpart;
  } elsif ( $self->svcnum
            && qsearchs('cust_svc',{'svcnum'=>$self->svcnum} )
          ) { #Case 2
    $svcpart = $self->cust_svc->svcpart;
  } else { # Case 3
    $svcpart = '';
  }

  if ($svcpart) { #Cases 1 and 2
    my %flags = map { $_->columnname, $_->columnflag } (
        qsearch ('part_svc_column', { svcpart => $svcpart } )
      );
    return grep { not ( defined($flags{$_}) && $flags{$_} eq 'X') } @vfields;
  } else { # Case 3
    return @vfields;
  } 
  return ();
}

=item label

svc_Common provides a fallback label subroutine that just returns the svcnum.

=cut

sub label {
  my $self = shift;
  cluck "warning: ". ref($self). " not loaded or missing label method; ".
        "using svcnum";
  $self->svcnum;
}

sub label_long {
  my $self = shift;
  $self->label(@_);
}

sub cust_main {
  my $self = shift;
  (($self->cust_svc || return)->cust_pkg || return)->cust_main || return
}

sub cust_linked {
  my $self = shift;
  defined($self->cust_main);
}

=item check

Checks the validity of fields in this record.

At present, this does nothing but call FS::Record::check (which, in turn, 
does nothing but run virtual field checks).

=cut

sub check {
  my $self = shift;
  $self->SUPER::check;
}

=item insert [ , OPTION => VALUE ... ]

Adds this record to the database.  If there is an error, returns the error,
otherwise returns false.

The additional fields pkgnum and svcpart (see L<FS::cust_svc>) should be 
defined.  An FS::cust_svc record will be created and inserted.

Currently available options are: I<jobnums>, I<child_objects> and
I<depend_jobnum>.

If I<jobnum> is set to an array reference, the jobnums of any export jobs will
be added to the referenced array.

If I<child_objects> is set to an array reference of FS::tablename objects
(for example, FS::svc_export_machine or FS::acct_snarf objects), they
will have their svcnum field set and will be inserted after this record,
but before any exports are run.  Each element of the array can also
optionally be a two-element array reference containing the child object
and the name of an alternate field to be filled in with the newly-inserted
svcnum, for example C<[ $svc_forward, 'srcsvc' ]>

If I<depend_jobnum> is set (to a scalar jobnum or an array reference of
jobnums), all provisioning jobs will have a dependancy on the supplied
jobnum(s) (they will not run until the specific job(s) complete(s)).

If I<export_args> is set to an array reference, the referenced list will be
passed to export commands.

=cut

sub insert {
  my $self = shift;
  my %options = @_;
  warn "[$me] insert called with options ".
       join(', ', map { "$_: $options{$_}" } keys %options ). "\n"
    if $DEBUG;

  my @jobnums = ();
  local $FS::queue::jobnums = \@jobnums;
  warn "[$me] insert: set \$FS::queue::jobnums to $FS::queue::jobnums\n"
    if $DEBUG;
  my $objects = $options{'child_objects'} || [];
  my $depend_jobnums = $options{'depend_jobnum'} || [];
  $depend_jobnums = [ $depend_jobnums ] unless ref($depend_jobnums);

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $svcnum = $self->svcnum;
  my $cust_svc = $svcnum ? qsearchs('cust_svc',{'svcnum'=>$self->svcnum}) : '';
  my $inserted_cust_svc = 0;
  #unless ( $svcnum ) {
  if ( !$svcnum or !$cust_svc ) {
    $cust_svc = new FS::cust_svc ( {
      #hua?# 'svcnum'  => $svcnum,
      'svcnum'  => $self->svcnum,
      'pkgnum'  => $self->pkgnum,
      'svcpart' => $self->svcpart,
    } );
    my $error = $cust_svc->insert;
    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }
    $inserted_cust_svc  = 1;
    $svcnum = $self->svcnum($cust_svc->svcnum);
  } else {
    #$cust_svc = qsearchs('cust_svc',{'svcnum'=>$self->svcnum});
    unless ( $cust_svc ) {
      $dbh->rollback if $oldAutoCommit;
      return "no cust_svc record found for svcnum ". $self->svcnum;
    }
    $self->pkgnum($cust_svc->pkgnum);
    $self->svcpart($cust_svc->svcpart);
  }

  my $error =    $self->preinsert_hook_first
              || $self->set_auto_inventory
              || $self->check
              || $self->_check_duplicate
              || $self->preinsert_hook
              || $self->SUPER::insert;
  if ( $error ) {
    if ( $inserted_cust_svc ) {
      my $derror = $cust_svc->delete;
      die $derror if $derror;
    }
    $dbh->rollback if $oldAutoCommit;
    return $error;
  }

  foreach my $object ( @$objects ) {
    my($field, $obj);
    if ( ref($object) eq 'ARRAY' ) {
      ($obj, $field) = @$object;
    } else {
      $obj = $object;
      $field = 'svcnum';
    }
    $obj->$field($self->svcnum);
    $error = $obj->insert;
    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }
  }

  #new-style exports!
  unless ( $noexport_hack ) {

    warn "[$me] insert: \$FS::queue::jobnums is $FS::queue::jobnums\n"
      if $DEBUG;

    my $export_args = $options{'export_args'} || [];

    foreach my $part_export ( $self->cust_svc->part_svc->part_export ) {
      my $error = $part_export->export_insert($self, @$export_args);
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return "exporting to ". $part_export->exporttype.
               " (transaction rolled back): $error";
      }
    }

    foreach my $depend_jobnum ( @$depend_jobnums ) {
      warn "[$me] inserting dependancies on supplied job $depend_jobnum\n"
        if $DEBUG;
      foreach my $jobnum ( @jobnums ) {
        my $queue = qsearchs('queue', { 'jobnum' => $jobnum } );
        warn "[$me] inserting dependancy for job $jobnum on $depend_jobnum\n"
          if $DEBUG;
        my $error = $queue->depend_insert($depend_jobnum);
        if ( $error ) {
          $dbh->rollback if $oldAutoCommit;
          return "error queuing job dependancy: $error";
        }
      }
    }

  }

  my $nms_ip_error = $self->nms_ip_insert;
  if ( $nms_ip_error ) {
    $dbh->rollback if $oldAutoCommit;
    return "error queuing IP insert: $nms_ip_error";
  }

  if ( exists $options{'jobnums'} ) {
    push @{ $options{'jobnums'} }, @jobnums;
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;

  '';
}

#fallbacks
sub preinsert_hook_first { ''; }
sub _check_duplcate { ''; }
sub preinsert_hook { ''; }
sub table_dupcheck_fields { (); }
sub prereplace_hook { ''; }
sub prereplace_hook_first { ''; }
sub predelete_hook { ''; }
sub predelete_hook_first { ''; }

=item delete [ , OPTION => VALUE ... ]

Deletes this account from the database.  If there is an error, returns the
error, otherwise returns false.

The corresponding FS::cust_svc record will be deleted as well.

=cut

sub delete {
  my $self = shift;
  my %options = @_;
  my $export_args = $options{'export_args'} || [];

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $error = 	$self->predelete_hook_first 
	      || $self->SUPER::delete
              || $self->export('delete', @$export_args)
	      || $self->return_inventory
              || $self->release_router
	      || $self->predelete_hook
	      || $self->cust_svc->delete
  ;
  if ( $error ) {
    $dbh->rollback if $oldAutoCommit;
    return $error;
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;

  '';
}

=item expire DATE

Currently this will only run expire exports if any are attached

=cut

sub expire {
  my($self,$date) = (shift,shift);

  return 'Expire date must be specified' unless $date;
    
  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $export_args = [$date];
  my $error = $self->export('expire', @$export_args);
  if ( $error ) {
    $dbh->rollback if $oldAutoCommit;
    return $error;
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;

  '';
}

=item replace [ OLD_RECORD ] [ HASHREF | OPTION => VALUE ]

Replaces OLD_RECORD with this one.  If there is an error, returns the error,
otherwise returns false.

Currently available options are: I<child_objects>, I<export_args> and
I<depend_jobnum>.

If I<child_objects> is set to an array reference of FS::tablename objects
(for example, FS::svc_export_machine or FS::acct_snarf objects), they
will have their svcnum field set and will be inserted or replaced after
this record, but before any exports are run.  Each element of the array
can also optionally be a two-element array reference containing the
child object and the name of an alternate field to be filled in with
the newly-inserted svcnum, for example C<[ $svc_forward, 'srcsvc' ]>

If I<depend_jobnum> is set (to a scalar jobnum or an array reference of
jobnums), all provisioning jobs will have a dependancy on the supplied
jobnum(s) (they will not run until the specific job(s) complete(s)).

If I<export_args> is set to an array reference, the referenced list will be
passed to export commands.

=cut

sub replace {
  my $new = shift;

  my $old = ( blessed($_[0]) && $_[0]->isa('FS::Record') )
              ? shift
              : $new->replace_old;

  my $options = 
    ( ref($_[0]) eq 'HASH' )
      ? shift
      : { @_ };

  my $objects = $options->{'child_objects'} || [];

  my @jobnums = ();
  local $FS::queue::jobnums = \@jobnums;
  warn "[$me] replace: set \$FS::queue::jobnums to $FS::queue::jobnums\n"
    if $DEBUG;
  my $depend_jobnums = $options->{'depend_jobnum'} || [];
  $depend_jobnums = [ $depend_jobnums ] unless ref($depend_jobnums);

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $error =  $new->prereplace_hook_first($old)
            || $new->set_auto_inventory($old)
            || $new->check; #redundant, but so any duplicate fields are
                            #maniuplated as appropriate (svc_phone.phonenum)
  if ( $error ) {
    $dbh->rollback if $oldAutoCommit;
    return $error;
  }

  #if ( $old->username ne $new->username || $old->domsvc != $new->domsvc ) {
  if ( grep { $old->$_ ne $new->$_ } $new->table_dupcheck_fields ) {

    $new->svcpart( $new->cust_svc->svcpart ) unless $new->svcpart;
    $error = $new->_check_duplicate;
    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }
  }

  $error = $new->SUPER::replace($old);
  if ($error) {
    $dbh->rollback if $oldAutoCommit;
    return $error;
  }

  foreach my $object ( @$objects ) {
    my($field, $obj);
    if ( ref($object) eq 'ARRAY' ) {
      ($obj, $field) = @$object;
    } else {
      $obj = $object;
      $field = 'svcnum';
    }
    $obj->$field($new->svcnum);

    my $oldobj = qsearchs( $obj->table, {
                             $field => $new->svcnum,
                             map { $_ => $obj->$_ } $obj->_svc_child_partfields,
                         });

    if ( $oldobj ) {
      my $pkey = $oldobj->primary_key;
      $obj->$pkey($oldobj->$pkey);
      $obj->replace($oldobj);
    } else {
      $error = $obj->insert;
    }
    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }
  }

  #new-style exports!
  unless ( $noexport_hack ) {

    warn "[$me] replace: \$FS::queue::jobnums is $FS::queue::jobnums\n"
      if $DEBUG;

    my $export_args = $options->{'export_args'} || [];

    #not quite false laziness, but same pattern as FS::svc_acct::replace and
    #FS::part_export::sqlradius::_export_replace.  List::Compare or something
    #would be useful but too much of a pain in the ass to deploy

    my @old_part_export = $old->cust_svc->part_svc->part_export;
    my %old_exportnum = map { $_->exportnum => 1 } @old_part_export;
    my @new_part_export = 
      $new->svcpart
        ? qsearchs('part_svc', { svcpart=>$new->svcpart } )->part_export
        : $new->cust_svc->part_svc->part_export;
    my %new_exportnum = map { $_->exportnum => 1 } @new_part_export;

    foreach my $delete_part_export (
      grep { ! $new_exportnum{$_->exportnum} } @old_part_export
    ) {
      my $error = $delete_part_export->export_delete($old, @$export_args);
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return "error deleting, export to ". $delete_part_export->exporttype.
               " (transaction rolled back): $error";
      }
    }

    foreach my $replace_part_export (
      grep { $old_exportnum{$_->exportnum} } @new_part_export
    ) {
      my $error =
        $replace_part_export->export_replace( $new, $old, @$export_args);
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return "error exporting to ". $replace_part_export->exporttype.
               " (transaction rolled back): $error";
      }
    }

    foreach my $insert_part_export (
      grep { ! $old_exportnum{$_->exportnum} } @new_part_export
    ) {
      my $error = $insert_part_export->export_insert($new, @$export_args );
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return "error inserting export to ". $insert_part_export->exporttype.
               " (transaction rolled back): $error";
      }
    }

    foreach my $depend_jobnum ( @$depend_jobnums ) {
      warn "[$me] inserting dependancies on supplied job $depend_jobnum\n"
        if $DEBUG;
      foreach my $jobnum ( @jobnums ) {
        my $queue = qsearchs('queue', { 'jobnum' => $jobnum } );
        warn "[$me] inserting dependancy for job $jobnum on $depend_jobnum\n"
          if $DEBUG;
        my $error = $queue->depend_insert($depend_jobnum);
        if ( $error ) {
          $dbh->rollback if $oldAutoCommit;
          return "error queuing job dependancy: $error";
        }
      }
    }

  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  '';
}

=item setfixed

Sets any fixed fields for this service (see L<FS::part_svc>).  If there is an
error, returns the error, otherwise returns the FS::part_svc object (use ref()
to test the return).  Usually called by the check method.

=cut

sub setfixed {
  my $self = shift;
  $self->setx('F', @_);
}

=item setdefault

Sets all fields to their defaults (see L<FS::part_svc>), overriding their
current values.  If there is an error, returns the error, otherwise returns
the FS::part_svc object (use ref() to test the return).

=cut

sub setdefault {
  my $self = shift;
  $self->setx('D', @_ );
}

=item set_default_and_fixed

=cut

sub set_default_and_fixed {
  my $self = shift;
  $self->setx( [ 'D', 'F' ], @_ );
}

=item setx FLAG | FLAG_ARRAYREF , [ CALLBACK_HASHREF ]

Sets fields according to the passed in flag or arrayref of flags.

Optionally, a hashref of field names and callback coderefs can be passed.
If a coderef exists for a given field name, instead of setting the field,
the coderef is called with the column value (part_svc_column.columnvalue)
as the single parameter.

=cut

sub setx {
  my $self = shift;
  my $x = shift;
  my @x = ref($x) ? @$x : ($x);
  my $coderef = scalar(@_) ? shift : $self->_fieldhandlers;

  my $error =
    $self->ut_numbern('svcnum')
  ;
  return $error if $error;

  my $part_svc = $self->part_svc;
  return "Unknown svcpart" unless $part_svc;

  #set default/fixed/whatever fields from part_svc

  foreach my $part_svc_column (
    grep { my $f = $_->columnflag; grep { $f eq $_ } @x } #columnflag in @x
    $part_svc->all_part_svc_column
  ) {

    my $columnname  = $part_svc_column->columnname;
    my $columnvalue = $part_svc_column->columnvalue;

    $columnvalue = &{ $coderef->{$columnname} }( $self, $columnvalue )
      if exists( $coderef->{$columnname} );
    $self->setfield( $columnname, $columnvalue );

  }

 $part_svc;

}

sub part_svc {
  my $self = shift;

  #get part_svc
  my $svcpart;
  if ( $self->get('svcpart') ) {
    $svcpart = $self->get('svcpart');
  } elsif ( $self->svcnum && qsearchs('cust_svc', {'svcnum'=>$self->svcnum}) ) {
    my $cust_svc = $self->cust_svc;
    return "Unknown svcnum" unless $cust_svc; 
    $svcpart = $cust_svc->svcpart;
  }

  qsearchs( 'part_svc', { 'svcpart' => $svcpart } );

}

=item svc_pbx

Returns the FS::svc_pbx record for this service, if any (see L<FS::svc_pbx>).

Only makes sense if the service has a pbxsvc field (currently, svc_phone and
svc_acct).

=cut

# XXX FS::h_svc_{acct,phone} could have a history-aware svc_pbx override

sub svc_pbx {
  my $self = shift;
  return '' unless $self->pbxsvc;
  qsearchs( 'svc_pbx', { 'svcnum' => $self->pbxsvc } );
}

=item pbx_title

Returns the title of the FS::svc_pbx record associated with this service, if
any.

Only makes sense if the service has a pbxsvc field (currently, svc_phone and
svc_acct).

=cut

sub pbx_title {
  my $self = shift;
  my $svc_pbx = $self->svc_pbx or return '';
  $svc_pbx->title;
}

=item pbx_select_hash %OPTIONS

Can be called as an object method or a class method.

Returns a hash SVCNUM => TITLE ...  representing the PBXes this customer
that may be associated with this service.

Currently available options are: I<pkgnum> I<svcpart>

Only makes sense if the service has a pbxsvc field (currently, svc_phone and
svc_acct).

=cut

#false laziness w/svc_acct::domain_select_hash
sub pbx_select_hash {
  my ($self, %options) = @_;
  my %pbxes = ();
  my $part_svc;
  my $cust_pkg;

  if (ref($self)) {
    $part_svc = $self->part_svc;
    $cust_pkg = $self->cust_svc->cust_pkg
      if $self->cust_svc;
  }

  $part_svc = qsearchs('part_svc', { 'svcpart' => $options{svcpart} })
    if $options{'svcpart'};

  $cust_pkg = qsearchs('cust_pkg', { 'pkgnum' => $options{pkgnum} })
    if $options{'pkgnum'};

  if ($part_svc && ( $part_svc->part_svc_column('pbxsvc')->columnflag eq 'S'
                  || $part_svc->part_svc_column('pbxsvc')->columnflag eq 'F')) {
    %pbxes = map { $_->svcnum => $_->title }
             map { qsearchs('svc_pbx', { 'svcnum' => $_ }) }
             split(',', $part_svc->part_svc_column('pbxsvc')->columnvalue);
  } elsif ($cust_pkg) { # && !$conf->exists('svc_acct-alldomains') ) {
    %pbxes = map { $_->svcnum => $_->title }
             map { qsearchs('svc_pbx', { 'svcnum' => $_->svcnum }) }
             map { qsearch('cust_svc', { 'pkgnum' => $_->pkgnum } ) }
             qsearch('cust_pkg', { 'custnum' => $cust_pkg->custnum });
  } else {
    #XXX agent-virt
    %pbxes = map { $_->svcnum => $_->title } qsearch('svc_pbx', {} );
  }

  if ($part_svc && $part_svc->part_svc_column('pbxsvc')->columnflag eq 'D') {
    my $svc_pbx = qsearchs('svc_pbx',
      { 'svcnum' => $part_svc->part_svc_column('pbxsvc')->columnvalue } );
    if ( $svc_pbx ) {
      $pbxes{$svc_pbx->svcnum}  = $svc_pbx->title;
    } else {
      warn "unknown svc_pbx.svcnum for part_svc_column pbxsvc: ".
           $part_svc->part_svc_column('pbxsvc')->columnvalue;

    }
  }

  (%pbxes);

}

=item set_auto_inventory

Sets any fields which auto-populate from inventory (see L<FS::part_svc>), and
also check any manually populated inventory fields.

If there is an error, returns the error, otherwise returns false.

=cut

sub set_auto_inventory {
  # don't try to do this during an upgrade
  return '' if $FS::CurrentUser::upgrade_hack;

  my $self = shift;
  my $old = @_ ? shift : '';

  my $error =
    $self->ut_numbern('svcnum')
  ;
  return $error if $error;

  my $part_svc = $self->part_svc;
  return "Unkonwn svcpart" unless $part_svc;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  #set default/fixed/whatever fields from part_svc
  my $table = $self->table;
  foreach my $field ( grep { $_ ne 'svcnum' } $self->fields ) {

    my $part_svc_column = $part_svc->part_svc_column($field);
    my $columnflag = $part_svc_column->columnflag;
    next unless $columnflag =~ /^[AM]$/;

    next if $columnflag eq 'A' && $self->$field() ne '';

    my $classnum = $part_svc_column->columnvalue;
    my %hash;

    if ( $columnflag eq 'A' && $self->$field() eq '' ) {
      $hash{'svcnum'} = '';
    } elsif ( $columnflag eq 'M' ) {
      return "Select inventory item for $field" unless $self->getfield($field);
      $hash{'item'} = $self->getfield($field);
      my $chosen_classnum = $self->getfield($field.'_classnum');
      if ( grep {$_ == $chosen_classnum} split(',', $classnum) ) {
        $classnum = $chosen_classnum;
      }
      # otherwise the chosen classnum is either (all), or somehow not on 
      # the list, so ignore it and choose the first item that's in any
      # class on the list
    }

    my $agentnums_sql = $FS::CurrentUser::CurrentUser->agentnums_sql(
      'null'  => 1,
      'table' => 'inventory_item',
    );

    my $inventory_item = qsearchs({
      'table'     => 'inventory_item',
      'hashref'   => \%hash,
      'extra_sql' => "AND classnum IN ($classnum) AND $agentnums_sql",
      'order_by'  => 'ORDER BY ( agentnum IS NULL ) '. #agent inventory first
                     ' LIMIT 1 FOR UPDATE',
    });

    unless ( $inventory_item ) {
      # should really only be shown if columnflag eq 'A'...
      $dbh->rollback if $oldAutoCommit;
      my $message = 'Out of ';
      my @classnums = split(',', $classnum);
      foreach ( @classnums ) {
        my $class = FS::inventory_class->by_key($_)
          or return "Can't find inventory_class.classnum $_";
        $message .= PL_N($class->classname);
        if ( scalar(@classnums) > 2 ) { # english is hard
          if ( $_ != $classnums[-1] ) {
            $message .= ', ';
          }
        }
        if ( scalar(@classnums) > 1 and $_ == $classnums[-2] ) {
          $message .= 'and ';
        }
      }
      return $message;
    }

    next if $columnflag eq 'M' && $inventory_item->svcnum == $self->svcnum;

    $self->setfield( $field, $inventory_item->item );
      #if $columnflag eq 'A' && $self->$field() eq '';

    # release the old inventory item, if there was one
    if ( $old && $old->$field() && $old->$field() ne $self->$field() ) {
      my $old_inv = qsearchs({
        'table'     => 'inventory_item',
        'hashref'   => { 
                         'svcnum'   => $old->svcnum,
                       },
        'extra_sql' => "AND classnum IN ($classnum) AND ".
          '( ( svc_field IS NOT NULL AND svc_field = '.$dbh->quote($field).' )'.
          '  OR ( svc_field IS NULL AND item = '. dbh->quote($old->$field).' )'.
          ')',
      });
      if ( $old_inv ) {
        $old_inv->svcnum('');
        $old_inv->svc_field('');
        my $oerror = $old_inv->replace;
        if ( $oerror ) {
          $dbh->rollback if $oldAutoCommit;
          return "Error unprovisioning inventory: $oerror";
        }
      } else {
        warn "old inventory_item not found for $field ". $self->$field;
      }
    }

    $inventory_item->svcnum( $self->svcnum );
    $inventory_item->svc_field( $field );
    my $ierror = $inventory_item->replace();
    if ( $ierror ) {
      $dbh->rollback if $oldAutoCommit;
      return "Error provisioning inventory: $ierror";
    }

  }

 $dbh->commit or die $dbh->errstr if $oldAutoCommit;

 '';

}

=item return_inventory

Release all inventory items attached to this service's fields.  Call
when unprovisioning the service.

=cut

sub return_inventory {
  my $self = shift;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  foreach my $inventory_item ( $self->inventory_item ) {
    $inventory_item->svcnum('');
    $inventory_item->svc_field('');
    my $error = $inventory_item->replace();
    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return "Error returning inventory: $error";
    }
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;

  '';
}

=item inventory_item

Returns the inventory items associated with this svc_ record, as
FS::inventory_item objects (see L<FS::inventory_item>.

=cut

sub inventory_item {
  my $self = shift;
  qsearch({
    'table'     => 'inventory_item',
    'hashref'   => { 'svcnum' => $self->svcnum, },
  });
}

=item release_router 

Delete any routers associated with this service.  This will release their
address blocks, also.

=cut

sub release_router {
  my $self = shift;
  my @routers = qsearch('router', { svcnum => $self->svcnum });
  foreach (@routers) {
    my $error = $_->delete;
    return "$error (removing router '".$_->routername."')" if $error;
  }
  '';
}


=item cust_svc

Returns the cust_svc record associated with this svc_ record, as a FS::cust_svc
object (see L<FS::cust_svc>).

=item suspend

Runs export_suspend callbacks.

=cut

sub suspend {
  my $self = shift;
  my %options = @_;
  my $export_args = $options{'export_args'} || [];
  $self->export('suspend', @$export_args);
}

=item unsuspend

Runs export_unsuspend callbacks.

=cut

sub unsuspend {
  my $self = shift;
  my %options = @_;
  my $export_args = $options{'export_args'} || [];
  $self->export('unsuspend', @$export_args);
}

=item export_links

Runs export_links callbacks and returns the links.

=cut

sub export_links {
  my $self = shift;
  my $return = [];
  $self->export('links', $return);
  $return;
}

=item export_getsettings

Runs export_getsettings callbacks and returns the two hashrefs.

=cut

sub export_getsettings {
  my $self = shift;
  my %settings = ();
  my %defaults = ();
  my $error = $self->export('getsettings', \%settings, \%defaults);
  if ( $error ) {
    warn "error running export_getsetings: $error";
    return ( { 'error' => $error }, {} );
  }
  ( \%settings, \%defaults );
}

=item export_getstatus

Runs export_getstatus callbacks and returns a two item list consisting of an
HTML status and a status hashref.

=cut

sub export_getstatus {
  my $self = shift;
  my $html = '';
  my %hash = ();
  my $error = $self->export('getstatus', \$html, \%hash);
  if ( $error ) {
    warn "error running export_getstatus: $error";
    return ( '', { 'error' => $error } );
  }
  ( $html, \%hash );
}

=item export_setstatus

Runs export_setstatus callbacks.  If there is an error, returns the error,
otherwise returns false.

=cut

sub export_setstatus { shift->_export_setstatus_X('setstatus', @_) }
sub export_setstatus_listadd { shift->_export_setstatus_X('setstatus_listadd', @_) }
sub export_setstatus_listdel { shift->_export_setstatus_X('setstatus_listdel', @_) }
sub export_setstatus_vacationadd { shift->_export_setstatus_X('setstatus_vacationadd', @_) }
sub export_setstatus_vacationdel { shift->_export_setstatus_X('setstatus_vacationdel', @_) }

sub _export_setstatus_X {
  my( $self, $method, @args ) = @_;
  my $error = $self->export($method, @args);
  if ( $error ) {
    warn "error running export_$method: $error";
    return $error;
  }
  '';
}

=item export HOOK [ EXPORT_ARGS ]

Runs the provided export hook (i.e. "suspend", "unsuspend") for this service.

=cut

sub export {
  my( $self, $method ) = ( shift, shift );

  $method = "export_$method" unless $method =~ /^export_/;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  #new-style exports!
  unless ( $noexport_hack ) {
    foreach my $part_export ( $self->cust_svc->part_svc->part_export ) {
      next unless $part_export->can($method);
      my $error = $part_export->$method($self, @_);
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return "error exporting $method event to ". $part_export->exporttype.
               " (transaction rolled back): $error";
      }
    }
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  '';

}

=item overlimit

Sets or retrieves overlimit date.

=cut

sub overlimit {
  my $self = shift;
  #$self->cust_svc->overlimit(@_);
  my $cust_svc = $self->cust_svc;
  unless ( $cust_svc ) { #wtf?
    my $error = "$me overlimit: missing cust_svc record for svc_acct svcnum ".
                $self->svcnum;
    if ( $overlimit_missing_cust_svc_nonfatal_kludge ) {
      cluck "$error; continuing anyway as requested";
      return '';
    } else {
      confess $error;
    }
  }
  $cust_svc->overlimit(@_);
}

=item cancel

Stub - returns false (no error) so derived classes don't need to define this
methods.  Called by the cancel method of FS::cust_pkg (see L<FS::cust_pkg>).

This method is called *before* the deletion step which actually deletes the
services.  This method should therefore only be used for "pre-deletion"
cancellation steps, if necessary.

=cut

sub cancel { ''; }

=item clone_suspended

Constructor used by FS::part_export::_export_suspend fallback.  Stub returning
same object for svc_ classes which don't implement a suspension fallback
(everything except svc_acct at the moment).  Document better.

=cut

sub clone_suspended {
  shift;
}

=item clone_kludge_unsuspend 

Constructor used by FS::part_export::_export_unsuspend fallback.  Stub returning
same object for svc_ classes which don't implement a suspension fallback
(everything except svc_acct at the moment).  Document better.

=cut

sub clone_kludge_unsuspend {
  shift;
}

=item find_duplicates MODE FIELDS...

Method used by _check_duplicate routines to find services with duplicate 
values in specified fields.  Set MODE to 'global' to search across all 
services, or 'export' to limit to those that share one or more exports 
with this service.  FIELDS is a list of field names; only services 
matching in all fields will be returned.  Empty fields will be skipped.

=cut

sub find_duplicates {
  my $self = shift;
  my $mode = shift;
  my @fields = @_;

  my %search = map { $_ => $self->getfield($_) } 
               grep { length($self->getfield($_)) } @fields;
  return () if !%search;
  my @dup = grep { ! $self->svcnum or $_->svcnum != $self->svcnum }
            qsearch( $self->table, \%search );
  return () if !@dup;
  return @dup if $mode eq 'global';
  die "incorrect find_duplicates mode '$mode'" if $mode ne 'export';

  my $exports = FS::part_export::export_info($self->table);
  my %conflict_svcparts;
  my $part_svc = $self->part_svc;
  foreach my $part_export ( $part_svc->part_export ) {
    %conflict_svcparts = map { $_->svcpart => 1 } $part_export->export_svc;
  }
  return grep { $conflict_svcparts{$_->cust_svc->svcpart} } @dup;
}

=item getstatus_html

=cut

sub getstatus_html {
  my $self = shift;

  my $part_svc = $self->cust_svc->part_svc;

  my $html = '';

  foreach my $export ( grep $_->can('export_getstatus'), $part_svc->part_export ) {
    my $export_html = '';
    my %hash = ();
    $export->export_getstatus( $self, \$export_html, \%hash );
    $html .= $export_html;
  }

  $html;

}

=item nms_ip_insert

=cut

sub nms_ip_insert {
  my $self = shift;
  my $conf = new FS::Conf;
  return '' unless grep { $self->table eq $_ }
                     $conf->config('nms-auto_add-svc_ips');
  my $ip_field = $self->table_info->{'ip_field'};

  my $queue = FS::queue->new( {
                'job'    => 'FS::NetworkMonitoringSystem::queued_add_router',
                'svcnum' => $self->svcnum,
  } );
  $queue->insert( 'FS::NetworkMonitoringSystem',
                  $self->$ip_field(),
                  $conf->config('nms-auto_add-community')
                );
}

=item nms_delip

=cut

sub nms_ip_delete {
#XXX not yet implemented
}

=item search_sql_field FIELD STRING

Class method which returns an SQL fragment to search for STRING in FIELD.

It is now case-insensitive by default.

=cut

sub search_sql_field {
  my( $class, $field, $string ) = @_;
  my $table = $class->table;
  my $q_string = dbh->quote($string);
  "LOWER($table.$field) = LOWER($q_string)";
}

#fallback for services that don't provide a search... 
sub search_sql {
  #my( $class, $string ) = @_;
  '1 = 0'; #false
}

=item search HASHREF

Class method which returns a qsearch hash expression to search for parameters
specified in HASHREF.

Parameters:

=over 4

=item unlinked - set to search for all unlinked services.  Overrides all other options.

=item agentnum

=item custnum

=item svcpart

=item ip_addr

=item pkgpart - arrayref

=item routernum - arrayref

=item sectornum - arrayref

=item towernum - arrayref

=item order_by

=back

=cut

# svc_broadband::search should eventually use this instead
sub search {
  my ($class, $params) = @_;

  my @from = (
    'LEFT JOIN cust_svc  USING ( svcnum  )',
    'LEFT JOIN part_svc  USING ( svcpart )',
    'LEFT JOIN cust_pkg  USING ( pkgnum  )',
    FS::UI::Web::join_cust_main('cust_pkg', 'cust_pkg'),
  );

  my @where = ();

  $class->_search_svc($params, \@from, \@where) if $class->can('_search_svc');

#  # domain
#  if ( $params->{'domain'} ) { 
#    my $svc_domain = qsearchs('svc_domain', { 'domain'=>$params->{'domain'} } );
#    #preserve previous behavior & bubble up an error if $svc_domain not found?
#    push @where, 'domsvc = '. $svc_domain->svcnum if $svc_domain;
#  }
#
#  # domsvc
#  if ( $params->{'domsvc'} =~ /^(\d+)$/ ) { 
#    push @where, "domsvc = $1";
#  }

  #unlinked
  push @where, 'pkgnum IS NULL' if $params->{'unlinked'};

  #agentnum
  if ( $params->{'agentnum'} =~ /^(\d+)$/ && $1 ) {
    push @where, "cust_main.agentnum = $1";
  }

  #custnum
  if ( $params->{'custnum'} =~ /^(\d+)$/ && $1 ) {
    push @where, "custnum = $1";
  }

  #customer status
  if ( $params->{'cust_status'} =~ /^([a-z]+)$/ ) {
    push @where, FS::cust_main->cust_status_sql . " = '$1'";
  }

  #customer balance
  if ( $params->{'balance'} =~ /^\s*(\-?\d*(\.\d{1,2})?)\s*$/ && length($1) ) {
    my $balance = $1;

    my $age = '';
    if ( $params->{'balance_days'} =~ /^\s*(\d*(\.\d{1,3})?)\s*$/ && length($1) ) {
      $age = time - 86400 * $1;
    }
    push @where, FS::cust_main->balance_date_sql($age) . " > $balance";
  }

  #payby
  if ( $params->{'payby'} && scalar(@{ $params->{'payby'} }) ) {
    my @payby = map "'$_'", grep /^(\w+)$/, @{ $params->{'payby'} };
    push @where, 'payby IN ('. join(',', @payby ). ')';
  }

  #pkgpart
  ##pkgpart, now properly untainted, can be arrayref
  #for my $pkgpart ( $params->{'pkgpart'} ) {
  #  if ( ref $pkgpart ) {
  #    my $where = join(',', map { /^(\d+)$/ ? $1 : () } @$pkgpart );
  #    push @where, "cust_pkg.pkgpart IN ($where)" if $where;
  #  }
  #  elsif ( $pkgpart =~ /^(\d+)$/ ) {
  #    push @where, "cust_pkg.pkgpart = $1";
  #  }
  #}
  if ( $params->{'pkgpart'} ) {
    my @pkgpart = ref( $params->{'pkgpart'} )
                    ? @{ $params->{'pkgpart'} }
                    : $params->{'pkgpart'}
                      ? ( $params->{'pkgpart'} )
                      : ();
    @pkgpart = grep /^(\d+)$/, @pkgpart;
    push @where, 'cust_pkg.pkgpart IN ('. join(',', @pkgpart ). ')' if @pkgpart;
  }

  #svcnum
  if ( $params->{'svcnum'} =~ /^(\d+)$/ ) {
    push @where, "svcnum = $1";
  }

  # svcpart
  if ( $params->{'svcpart'} ) {
    my @svcpart = ref( $params->{'svcpart'} )
                    ? @{ $params->{'svcpart'} }
                    : $params->{'svcpart'}
                      ? ( $params->{'svcpart'} )
                      : ();
    @svcpart = grep /^(\d+)$/, @svcpart;
    push @where, 'svcpart IN ('. join(',', @svcpart ). ')' if @svcpart;
  }

  if ( $params->{'exportnum'} =~ /^(\d+)$/ ) {
    push @from, ' LEFT JOIN export_svc USING ( svcpart )';
    push @where, "exportnum = $1";
  }

#  # sector and tower
#  my @where_sector = $class->tower_sector_sql($params);
#  if ( @where_sector ) {
#    push @where, @where_sector;
#    push @from, ' LEFT JOIN tower_sector USING ( sectornum )';
#  }

  # here is the agent virtualization
  #if ($params->{CurrentUser}) {
  #  my $access_user =
  #    qsearchs('access_user', { username => $params->{CurrentUser} });
  #
  #  if ($access_user) {
  #    push @where, $access_user->agentnums_sql('table'=>'cust_main');
  #  }else{
  #    push @where, "1=0";
  #  }
  #} else {
    push @where, $FS::CurrentUser::CurrentUser->agentnums_sql(
                   'table'      => 'cust_main',
                   'null_right' => 'View/link unlinked services',
                 );
  #}

  push @where, @{ $params->{'where'} } if $params->{'where'};

  my $addl_from = join(' ', @from);
  my $extra_sql = scalar(@where) ? ' WHERE '. join(' AND ', @where) : '';

  my $table = $class->table;

  my $count_query = "SELECT COUNT(*) FROM $table $addl_from $extra_sql";
  #if ( keys %svc_X ) {
  #  $count_query .= ' WHERE '.
  #                    join(' AND ', map "$_ = ". dbh->quote($svc_X{$_}),
  #                                      keys %svc_X
  #                        );
  #}

  {
    'table'       => $table,
    'hashref'     => {},
    'select'      => join(', ',
                       "$table.*",
                       'part_svc.svc',
                       'cust_main.custnum',
                       @{ $params->{'addl_select'} || [] },
                       FS::UI::Web::cust_sql_fields($params->{'cust_fields'}),
                     ),
    'addl_from'   => $addl_from,
    'extra_sql'   => $extra_sql,
    'order_by'    => $params->{'order_by'},
    'count_query' => $count_query,
  };

}

=back

=head1 BUGS

The setfixed method return value.

B<export> method isn't used by insert and replace methods yet.

=head1 SEE ALSO

L<FS::Record>, L<FS::cust_svc>, L<FS::part_svc>, L<FS::cust_pkg>, schema.html
from the base documentation.

=cut

1;

