package FS::part_pkg_taxrate;

use strict;
use vars qw( @ISA );
use Date::Parse;
use DateTime;
use DateTime::Format::Strptime;
use FS::Record qw( qsearch qsearchs dbh );
use FS::part_pkg_taxproduct;
use FS::Misc qw(csv_from_fixed);

@ISA = qw(FS::Record);

=head1 NAME

FS::part_pkg_taxrate - Object methods for part_pkg_taxrate records

=head1 SYNOPSIS

  use FS::part_pkg_taxrate;

  $record = new FS::part_pkg_taxrate \%hash;
  $record = new FS::part_pkg_taxrate { 'column' => 'value' };

  $error = $record->insert;

  $error = $new_record->replace($old_record);

  $error = $record->delete;

  $error = $record->check;

=head1 DESCRIPTION

An FS::part_pkg_taxrate object maps packages onto tax rates.
FS::part_pkg_taxrate inherits from FS::Record.  The following fields are
currently supported:

=over 4

=item pkgtaxratenum

Primary key

=item data_vendor

Tax data vendor

=item geocode

Tax vendor location code

=item taxproductnum

Class of package for tax purposes, Index into FS::part_pkg_taxproduct

=item city

city

=item county

county

=item state

state

=item local

local

=item country

country

=item taxclassnum

Class of tax index into FS::tax_taxclass and FS::tax_rate

=item taxclassnumtaxed

Class of tax taxed by this entry.

=item taxable

taxable

=item effdate

effdate

=back

=head1 METHODS

=over 4

=item new HASHREF

Creates a new customer (location), package, tax rate mapping.  To add the
mapping to the database, see L<"insert">.

Note that this stores the hash reference, not a distinct copy of the hash it
points to.  You can ask the object for a copy with the I<hash> method.

=cut

sub table { 'part_pkg_taxrate'; }

=item insert

Adds this record to the database.  If there is an error, returns the error,
otherwise returns false.

=cut

=item delete

Delete this record from the database.

=cut

=item replace OLD_RECORD

Replaces the OLD_RECORD with this one in the database.  If there is an error,
returns the error, otherwise returns false.

=cut

=item check

Checks all fields to make sure this is a valid tax rate mapping.  If there is
an error, returns the error, otherwise returns false.  Called by the insert
and replace methods.

=cut

sub check {
  my $self = shift;

  my $error = 
    $self->ut_numbern('pkgtaxratenum')
    || $self->ut_textn('data_vendor')
    || $self->ut_textn('geocode')
    || $self->
         ut_foreign_key('taxproductnum', 'part_pkg_taxproduct', 'taxproductnum')
    || $self->ut_textn('city')
    || $self->ut_textn('county')
    || $self->ut_textn('state')
    || $self->ut_textn('local')
    || $self->ut_text('country')
    || $self->ut_foreign_keyn('taxclassnumtaxed', 'tax_class', 'taxclassnum')
    || $self->ut_foreign_key('taxclassnum', 'tax_class', 'taxclassnum')
    || $self->ut_snumbern('effdate')
    || $self->ut_enum('taxable', [ 'Y', '' ])
  ;
  return $error if $error;

  $self->SUPER::check;
}

=item batch_import

Loads part_pkg_taxrate records from an external CSV file.  If there is
an error, returns the error, otherwise returns false. 

=cut 

sub batch_import {
  my ($param, $job) = @_;

  my $fh = $param->{filehandle};
  my $format = $param->{'format'};

  my $imported = 0;
  my @fields;
  my $hook;

  my @column_lengths = ();
  my @column_callbacks = ();
  if ( $format eq 'cch-fixed' || $format eq 'cch-fixed-update' ) {
    $format =~ s/-fixed//;
    my $date_format = sub { my $r='';
                            /^(\d{4})(\d{2})(\d{2})$/ && ($r="$3/$2/$1");
                            $r;
                          };
    $column_callbacks[16] = $date_format;
    push @column_lengths, qw( 28 25 2 1 10 4 30 3 100 2 2 2 2 1 2 2 8 1 );
    push @column_lengths, 1 if $format eq 'cch-update';
  }

  my $line;
  my ( $count, $last, $min_sec ) = (0, time, 5); #progressbar
  if ( $job || scalar(@column_callbacks) ) {
    my $error =
      csv_from_fixed(\$fh, \$count, \@column_lengths, \@column_callbacks);
    return $error if $error;
  }

  if ( $format eq 'cch' ||  $format eq 'cch-update' ) {
    @fields = qw( city county state local geocode group groupdesc item
                  itemdesc provider customer taxtypetaxed taxcattaxed
                  taxable taxtype taxcat effdate rectype );
    push @fields, 'actionflag' if $format eq 'cch-update';

    $imported++ if $format eq 'cch-update';  #empty file ok

    $hook = sub { 
      my $hash = shift;

      unless ( $hash->{'rectype'} eq 'R' or $hash->{'rectype'} eq 'T' ) {
        delete($hash->{$_}) for (keys %$hash);
        return;
      }

      $hash->{'data_vendor'} = 'cch';

      my %providers = ( '00' => 'Regulated LEC',
                        '01' => 'Regulated IXC',
                        '02' => 'Unregulated LEC',
                        '03' => 'Unregulated IXC',
                        '04' => 'ISP',
                        '05' => 'Wireless',
                      );

      my %customers = ( '00' => 'Residential',
                        '01' => 'Commercial',
                        '02' => 'Industrial',
                        '09' => 'Lifeline',
                        '10' => 'Senior Citizen',
                      );

      my $taxproduct =
        join(':', map{ $hash->{$_} } qw(group item provider customer ) );

      my %part_pkg_taxproduct = ( 'data_vendor' => 'cch', 
                                  'taxproduct' => $taxproduct,
                                );

      my $part_pkg_taxproduct = qsearchs( 'part_pkg_taxproduct', 
                                          { %part_pkg_taxproduct }
                                        );

      unless ($part_pkg_taxproduct) {
        if (($hash->{'actionfield'} || '') eq 'D') {
          warn "WARNING: Can't find part_pkg_taxproduct for txmatrix deletion: ".
            join(" ", map { "$_ => ". $hash->{$_} } @fields) .
            " (ignored)\n";
          next;
        }

        $part_pkg_taxproduct{'description'} = 
          join(' : ', (map{ $hash->{$_} } qw(groupdesc itemdesc)),
                      $providers{$hash->{'provider'}} || '',
                      $customers{$hash->{'customer'}} || '',
              );
        $part_pkg_taxproduct = new FS::part_pkg_taxproduct \%part_pkg_taxproduct;
        my $error = $part_pkg_taxproduct->insert;
        return "Error inserting tax product (part_pkg_taxproduct): $error"
          if $error;

      }
      $hash->{'taxproductnum'} = $part_pkg_taxproduct->taxproductnum;

      delete($hash->{$_})
        for qw(group groupdesc item itemdesc provider customer rectype );
      
      # resolve the taxtype/taxcat fields to taxclassnums

      my %map = ( 'taxclassnum'      => [ 'taxtype', 'taxcat' ],
                  'taxclassnumtaxed' => [ 'taxtypetaxed', 'taxcattaxed' ],
                );

      for my $item (keys %map) {
        my $class = join(':', map($hash->{$_}, @{$map{$item}}));
        my $tax_class =
          qsearchs( 'tax_class',
                    { data_vendor => 'cch',
                      'taxclass' => $class,
                    }
                  );
        if ( $tax_class ) {
          $hash->{$item} = $tax_class->taxclassnum;
        } elsif ($class ne ':' and ($hash->{actionflag} || '') eq 'D') {
          # return "Can't find tax class for txmatrix deletion: ".
          warn "WARNING: Can't find tax class $class for txmatrix deletion (ignored)\n";
          return ''; # don't delete the record, then
        }

        delete($hash->{$_}) foreach @{$map{$item}};
      }

      my $parser = new DateTime::Format::Strptime( pattern => "%m/%d/%Y",
                                                   time_zone => 'floating',
                                                 );
      my $dt = $parser->parse_datetime( $hash->{'effdate'} );
      return "Can't parse effdate ". $hash->{'effdate'}. ': '. $parser->errstr
        unless $dt;
      $hash->{'effdate'} = $dt->epoch;
 
      $hash->{'country'} = 'US'; # CA is available

      $hash->{'taxable'} = '' if ($hash->{'taxable'} eq 'N');

      if (exists($hash->{actionflag}) && $hash->{actionflag} eq 'D') {
        delete($hash->{actionflag});

        foreach my $intfield (qw( taxproductnum taxclassnum effdate )) {
          if ( $hash->{$intfield} eq '' ) {
            return "$intfield is empty in search! -- ".
                   join(" ", map { "$_ => *". $hash->{$_}. '*' } keys(%$hash) );
          }
        }

        my @part_pkg_taxrate = qsearch('part_pkg_taxrate', $hash);
        unless ( scalar(@part_pkg_taxrate) || $param->{'delete_only'} ) {
          if ( $hash->{taxproductnum} ) {
            my $taxproduct =
              qsearchs( 'part_pkg_taxproduct',
                        { 'taxproductnum' => $hash->{taxproductnum} }
                      );
            $hash->{taxproductnum} .= ' ( '. $taxproduct->taxproduct. ' )'
              if $taxproduct;
          }
          warn "WARNING: Can't find part_pkg_taxrate to delete: ".
                 join(" ", map { "$_ => *". $hash->{$_}. '*' } keys(%$hash) );
        }

        foreach my $part_pkg_taxrate (@part_pkg_taxrate) {
          my $error = $part_pkg_taxrate->delete;
          return $error if $error;
        }

        delete($hash->{$_}) foreach (keys %$hash);
      }

      delete($hash->{actionflag});

      '';
    };

  } elsif ( $format eq 'extended' ) {
    die "unimplemented\n";
    @fields = qw( );
    $hook = sub {};
  } else {
    die "unknown format $format";
  }

  eval "use Text::CSV_XS;";
  die $@ if $@;

  my $csv = new Text::CSV_XS;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;
  
  while ( defined($line=<$fh>) ) {
    $csv->parse($line) or do {
      $dbh->rollback if $oldAutoCommit;
      return "can't parse: ". $csv->error_input();
    };


    if ( $job ) {  # progress bar
      if ( time - $min_sec > $last ) {
        my $error = $job->update_statustext(
          int( 100 * $imported / $count ). ",Importing tax matrix"
        );
        die $error if $error;
        $last = time;
      }
    }

    my @columns = $csv->fields();

    my %part_pkg_taxrate = ( 'data_vendor' => $format );
    foreach my $field ( @fields ) {
      $part_pkg_taxrate{$field} = shift @columns; 
    }
    if ( scalar( @columns ) ) {
      $dbh->rollback if $oldAutoCommit;
      return "Unexpected trailing columns in line (wrong format?) importing part_pkg_taxrate: $line";
    }

    my $error = &{$hook}(\%part_pkg_taxrate);
    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }
    next unless scalar(keys %part_pkg_taxrate);


    my $part_pkg_taxrate = new FS::part_pkg_taxrate( \%part_pkg_taxrate );
    $error = $part_pkg_taxrate->insert;

    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return "can't insert part_pkg_taxrate for $line: $error";
    }

    $imported++;
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;

  return "Empty file!" unless ( $imported || $format eq 'cch-update' );

  ''; #no error

}

=back

=head1 BUGS

=head1 SEE ALSO

L<FS::Record>, schema.html from the base documentation.

=cut

1;


