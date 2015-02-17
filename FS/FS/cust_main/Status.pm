package FS::cust_main::Status;

use strict;
use vars qw( $conf ); # $module ); #$DEBUG $me );
use Tie::IxHash;
use FS::UID;
use FS::cust_pkg;

#$DEBUG = 0;
#$me = '[FS::cust_main::Status]';

install_callback FS::UID sub { 
  $conf = new FS::Conf;
  #$module = $conf->config('cust_main-status_module') || 'Classic';
};

=head1 NAME

FS::cust_main::Status - Status mixin for cust_main

=head1 SYNOPSIS

=head1 DESCRIPTION

These methods are available on FS::cust_main objects:

=head1 METHODS

=over 4

=item statuscolors

Returns an (ordered with Tie::IxHash) hash reference of possible status
names and colors.

=cut

sub statuscolors {
  #my $self = shift; #i guess i'm a class method

  my %statuscolors;

  my $module = $conf->config('cust_main-status_module') || 'Classic';

  if ( $module eq 'Classic' ) {
    tie %statuscolors, 'Tie::IxHash',
      'prospect'  => '7e0079', #'000000', #black?  naw, purple
      'active'    => '00CC00', #green
      'ordered'   => '009999', #teal? cyan?
      'inactive'  => '0000CC', #blue
      'suspended' => 'FF9900', #yellow
      'cancelled' => 'FF0000', #red
    ;
  } elsif ( $module eq 'Recurring' ) {
    tie %statuscolors, 'Tie::IxHash',
      'prospect'  => '7e0079', #'000000', #black?  naw, purple
      'active'    => '00CC00', #green
      'ordered'   => '009999', #teal? cyan?
      'suspended' => 'FF9900', #yellow
      'cancelled' => 'FF0000', #red
      'inactive'  => '0000CC', #blue
    ;
  } else {
    die "unknown status module $module";
  }

  \%statuscolors;

}

sub statuslabels {
  #my $self = shift; #i guess i'm a class method

  my %statuslabels = (
      'prospect'  => 'No packages',
      'active'    => 'Active',
      'ordered'   => 'Ordered',
      'inactive'  => 'Inactive',
      'suspended' => 'Suspended',
      'cancelled' => 'Cancelled',
  );

  \%statuslabels;
}

=item cancelled_sql

=cut

sub cancelled_sql {
  my $self = shift;

  my $recurring_sql = FS::cust_pkg->recurring_sql;
  my $cancelled_sql = FS::cust_pkg->cancelled_sql;
  my $select_count_pkgs = $self->select_count_pkgs_sql;

  my $sql = "
        0 < ( $select_count_pkgs )
    AND 0 = ( $select_count_pkgs AND $recurring_sql
                  AND ( cust_pkg.cancel IS NULL OR cust_pkg.cancel = 0 )
            )
    AND 0 < ( $select_count_pkgs AND $cancelled_sql   )
  ";

  my $module = $conf->config('cust_main-status_module') || 'Classic';

  if ( $module eq 'Classic' ) {
    $sql .=
      " AND 0 = (  $select_count_pkgs AND ". FS::cust_pkg->inactive_sql. " ) ";
  #} elsif ( $module eq 'Recurring' ) {
  #} else {
  #  die "unknown status module $module";
  }

  $sql;

}

=back

=head1 CLASS METHODS

=over 4

=item churn_sql START, END

Returns an SQL statement for the customer churn status query.  The columns
returned are the custnum and the number of active, suspended, and cancelled
packages (excluding one-time packages) at the start date ("s_active",
"s_suspended", and "s_cancelled") and the end date ("e_active", etc.).

=cut

# not sure this belongs here...FS::cust_main::Packages?

sub churn_sql {
  my $self = shift;
  my ($speriod, $eperiod) = @_;

  my $s_sql = FS::h_cust_pkg->status_as_of_sql($speriod);
  my $e_sql = FS::h_cust_pkg->status_as_of_sql($eperiod);

  my @select = (
    'custnum',
    'COALESCE(SUM(s.is_active::int),0)     as s_active',
    'COALESCE(SUM(s.is_suspended::int),0)  as s_suspended',
    'COALESCE(SUM(s.is_cancelled::int),0)  as s_cancelled',
    'COALESCE(SUM(e.is_active::int),0)     as e_active',
    'COALESCE(SUM(e.is_suspended::int),0)  as e_suspended',
    'COALESCE(SUM(e.is_cancelled::int),0)  as e_cancelled',
  );
  my $from = "($s_sql) AS s FULL JOIN ($e_sql) AS e USING (custnum)";

  return "SELECT ".join(',', @select)." FROM $from GROUP BY custnum";
}

=head1 BUGS

=head1 SEE ALSO

L<FS::cust_main>

=cut

1;

