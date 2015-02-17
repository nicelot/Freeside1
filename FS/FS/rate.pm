package FS::rate;
use base qw(FS::Record);

use strict;
use vars qw( $DEBUG );
use FS::Record qw( qsearch qsearchs dbh fields );
use FS::rate_detail;

$DEBUG = 0;

=head1 NAME

FS::rate - Object methods for rate records

=head1 SYNOPSIS

  use FS::rate;

  $record = new FS::rate \%hash;
  $record = new FS::rate { 'column' => 'value' };

  $error = $record->insert;

  $error = $new_record->replace($old_record);

  $error = $record->delete;

  $error = $record->check;

=head1 DESCRIPTION

An FS::rate object represents an rate plan.  FS::rate inherits from
FS::Record.  The following fields are currently supported:

=over 4

=item ratenum

primary key

=item ratename

Rate name

=item agentnum

Optional agent (see L<FS::agent>) for agent-virtualized rates.

=item default_detailnum 

Optional rate detail to apply when a call doesn't match any region in the 
rate plan. If this is not set, the call will either be left unrated (though
it may still be processed under a different pricing addon package), or be 
marked as 'skipped', or throw a fatal error, depending on the setting of 
the 'ignore_unrateable' package option.

=item 

=back

=head1 METHODS

=over 4

=item new HASHREF

Creates a new rate plan.  To add the rate plan to the database, see L<"insert">.

Note that this stores the hash reference, not a distinct copy of the hash it
points to.  You can ask the object for a copy with the I<hash> method.

=cut

# the new method can be inherited from FS::Record, if a table method is defined

sub table { 'rate'; }

=item insert [ , OPTION => VALUE ... ]

Adds this record to the database.  If there is an error, returns the error,
otherwise returns false.

Currently available options are: I<rate_detail>

If I<rate_detail> is set to an array reference of FS::rate_detail objects, the
objects will have their ratenum field set and will be inserted after this
record.

=cut

sub insert {
  my $self = shift;
  my %options = @_;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $error = $self->check;
  return $error if $error;

  $error = $self->SUPER::insert;
  if ( $error ) {
    $dbh->rollback if $oldAutoCommit;
    return $error;
  }

  if ( $options{'rate_detail'} ) {

    my( $num, $last, $min_sec ) = (0, time, 5); #progressbar foo

    foreach my $rate_detail ( @{$options{'rate_detail'}} ) {

      $rate_detail->ratenum($self->ratenum);
      $error = $rate_detail->insert;
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return $error;
      }

      if ( $options{'job'} ) {
        $num++;
        if ( time - $min_sec > $last ) {
          my $error = $options{'job'}->update_statustext(
            int( 100 * $num / scalar( @{$options{'rate_detail'}} ) )
          );
          if ( $error ) {
            $dbh->rollback if $oldAutoCommit;
            return $error;
          }
          $last = time;
        }
      }

    }
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;

  '';
}



=item delete

Delete this record from the database.

=cut

# the delete method can be inherited from FS::Record

=item replace OLD_RECORD [ , OPTION => VALUE ... ]

Replaces the OLD_RECORD with this one in the database.  If there is an error,
returns the error, otherwise returns false.

Currently available options are: I<rate_detail>

If I<rate_detail> is set to an array reference of FS::rate_detail objects, the
objects will have their ratenum field set and will be inserted after this
record.  Any existing rate_detail records associated with this record will be
deleted.

=cut

sub replace {
  my ($new, $old) = (shift, shift);
  my %options = @_;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

#  my @old_rate_detail = ();
#  @old_rate_detail = $old->rate_detail if $options{'rate_detail'};

  my $error = $new->SUPER::replace($old);
  if ($error) {
    $dbh->rollback if $oldAutoCommit;
    return $error;
  }

#  foreach my $old_rate_detail ( @old_rate_detail ) {
#
#    my $error = $old_rate_detail->delete;
#    if ($error) {
#      $dbh->rollback if $oldAutoCommit;
#      return $error;
#    }
#
#    if ( $options{'job'} ) {
#      $num++;
#      if ( time - $min_sec > $last ) {
#        my $error = $options{'job'}->update_statustext(
#          int( 50 * $num / scalar( @old_rate_detail ) )
#        );
#        if ( $error ) {
#          $dbh->rollback if $oldAutoCommit;
#          return $error;
#        }
#        $last = time;
#      }
#    }
#
#  }
  if ( $options{'rate_detail'} ) {
    my $sth = $dbh->prepare('DELETE FROM rate_detail WHERE ratenum = ?') or do {
      $dbh->rollback if $oldAutoCommit;
      return $dbh->errstr;
    };
  
    $sth->execute($old->ratenum) or do {
      $dbh->rollback if $oldAutoCommit;
      return $sth->errstr;
    };

    my( $num, $last, $min_sec ) = (0, time, 5); #progresbar foo
#  $num = 0;
    foreach my $rate_detail ( @{$options{'rate_detail'}} ) {
  
      $rate_detail->ratenum($new->ratenum);
      $error = $rate_detail->insert;
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return $error;
      }
  
      if ( $options{'job'} ) {
        $num++;
        if ( time - $min_sec > $last ) {
          my $error = $options{'job'}->update_statustext(
            int( 100 * $num / scalar( @{$options{'rate_detail'}} ) )
          );
          if ( $error ) {
            $dbh->rollback if $oldAutoCommit;
            return $error;
          }
          $last = time;
        }
      }
  
    }

  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  '';

}

=item check

Checks all fields to make sure this is a valid rate plan.  If there is
an error, returns the error, otherwise returns false.  Called by the insert
and replace methods.

=cut

sub check {
  my $self = shift;

  my $error =
       $self->ut_numbern('ratenum')
    || $self->ut_text('ratename')
    #|| $self->ut_foreign_keyn('agentnum', 'agent', 'agentnum')
    || $self->ut_numbern('default_detailnum')
  ;
  return $error if $error;

  $self->SUPER::check;
}

=item dest_detail REGIONNUM | RATE_REGION_OBJECTD | HASHREF

Returns the rate detail (see L<FS::rate_detail>) for this rate to the
specificed destination. If no rate can be found, returns the default 
rate if there is one, and an empty string otherwise.

Destination can be specified as an FS::rate_detail object or regionnum
(see L<FS::rate_detail>), or as a hashref containing the following keys:

=over 2

=item I<countrycode> - required.

=item I<phonenum> - required.

=item I<weektime> - optional.  Specifies a time in seconds from the start 
of the week, and will return a timed rate (one with a non-null I<ratetimenum>)
if one exists at that time.  If not, returns a non-timed rate.

=item I<cdrtypenum> - optional.  Specifies a value for the cdrtypenum 
field, and will return a rate matching that, if one exists.  If not, returns 
a rate with null cdrtypenum.

=cut

sub dest_detail {
  my $self = shift;

  my( $regionnum, $weektime, $cdrtypenum );
  if ( ref($_[0]) eq 'HASH' ) {

    my $countrycode = $_[0]->{'countrycode'};
    my $phonenum    = $_[0]->{'phonenum'};
    $weektime       = $_[0]->{'weektime'};
    $cdrtypenum     = $_[0]->{'cdrtypenum'} || '';

    #find a rate prefix, first look at most specific, then fewer digits,
    # finally trying the country code only
    my $rate_prefix = '';
    $rate_prefix = qsearchs({
        'table'     => 'rate_prefix',
        'addl_from' => ' JOIN rate_region USING (regionnum)',
        'hashref'   => {
          'countrycode' => $countrycode,
          'npa'         => $phonenum,
        },
        'extra_sql' => ' AND exact_match = \'Y\''
    });
    if (!$rate_prefix) {
      for my $len ( reverse(1..10) ) {
        $rate_prefix = qsearchs('rate_prefix', {
          'countrycode' => $countrycode,
          #'npa'         => { op=> 'LIKE', value=> substr($number, 0, $len) }
          'npa'         => substr($phonenum, 0, $len),
        } ) and last;
      }
      $rate_prefix ||= qsearchs('rate_prefix', {
        'countrycode' => $countrycode,
        'npa'         => '',
      });
    }

    return '' unless $rate_prefix;

    $regionnum = $rate_prefix->regionnum;

  } else {
    $regionnum = ref($_[0]) ? shift->regionnum : shift;
  }

  my %hash = (
    'ratenum'         => $self->ratenum,
    'dest_regionnum'  => $regionnum,
  );

  # find all rates matching ratenum, regionnum, cdrtypenum
  my @details = qsearch( 'rate_detail', { 
      %hash,
      'cdrtypenum' => $cdrtypenum
    });
  # find all rates maching ratenum, regionnum and null cdrtypenum
  if ( !@details and $cdrtypenum ) {
    @details = qsearch( 'rate_detail', {
        %hash,
        'cdrtypenum' => ''
      });
  }
  # find one of those matching weektime
  if ( defined($weektime) ) {
    my @exact = grep { 
      my $rate_time = $_->rate_time;
      $rate_time && $rate_time->contains($weektime)
    } @details;
    if ( @exact == 1 ) {
      return $exact[0];
    }
    elsif ( @exact > 1 ) {
      die "overlapping rate_detail times (region $regionnum, time $weektime)\n"
    }
    # else @exact == 0
  }
  # if not found or there is no weektime, find one matching null weektime
  foreach (@details) {
    return $_ if $_->ratetimenum eq '';
  }
  # if still nothing, return the global default rate for this plan
  return $self->default_detail;
}

=item rate_detail

Returns all region-specific details  (see L<FS::rate_detail>) for this rate.

=back

=item default_detail

Returns the default rate detail, if there is one.

=cut

sub default_detail {
  my $self = shift;
  $self->default_detailnum ?
    FS::rate_detail->by_key($self->default_detailnum) : ''
}

=head1 SUBROUTINES

=over 4

=item process

Job-queue processor for web interface adds/edits

=cut

use Data::Dumper;
sub process {
  my $job = shift;
  my $param = shift;
  warn Dumper($param) if $DEBUG;

  my $old = qsearchs('rate', { 'ratenum' => $param->{'ratenum'} } )
    if $param->{'ratenum'};

  my @rate_detail = map {

    my $regionnum = $_->regionnum;
    if ( $param->{"sec_granularity$regionnum"} ) {

      new FS::rate_detail {
        'dest_regionnum'  => $regionnum,
        map { $_ => $param->{"$_$regionnum"} }
            qw( min_included min_charge sec_granularity )
            #qw( min_included conn_charge conn_sec min_charge sec_granularity )
      };

    } else {

      new FS::rate_detail {
        'dest_regionnum'  => $regionnum,
        'min_included'    => 0,
        'conn_charge'     => 0,
        'conn_sec'        => 0,
        'conn_charge'     => 0,
        'min_charge'      => 0,
        'sec_granularity' => '60'
      };

    }
    
  } qsearch('rate_region', {} );
  
  my $rate = new FS::rate {
    map { $_ => $param->{$_} }
        fields('rate')
  };

  my $error = '';
  if ( $param->{'ratenum'} ) {
    warn "$rate replacing $old (". $param->{'ratenum'}. ")\n" if $DEBUG;

    my @param = ( 'job'=>$job );
    push @param, 'rate_detail'=>\@rate_detail
      unless $param->{'preserve_rate_detail'};

    $error = $rate->replace( $old, @param );

  } else {
    warn "inserting $rate\n" if $DEBUG;
    $error = $rate->insert( 'rate_detail' => \@rate_detail,
                            'job'         => $job,
                          );
    #$ratenum = $rate->getfield('ratenum');
  }

  die "$error\n" if $error;

}

=head1 BUGS

=head1 SEE ALSO

L<FS::Record>, schema.html from the base documentation.

=cut

1;

