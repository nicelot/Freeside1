package FS::Report::FCC_477;
use base qw( FS::Report );

use strict;
use vars qw( @upload @download @technology @part2aoption @part2boption
             %states
             $DEBUG
           );
use FS::Record qw( dbh );

$DEBUG = 1;

=head1 NAME

FS::Report::FCC_477 - Routines for FCC Form 477 reports

=head1 SYNOPSIS

=head1 BUGS

Documentation.

=head1 SEE ALSO

=cut

@upload = qw(
 <200kbps
 200-768kbps
 768kbps-1.5mbps
 1.5-3mpbs
 3-6mbps
 6-10mbps
 10-25mbps
 25-100mbps
 >100mbps
);

@download = qw(
 200-768kbps
 768kbps-1.5mbps
 1.5-3mbps
 3-6mbps
 6-10mbps
 10-25mbps
 25-100mbps
 >100mbps
);

@technology = (
  'Asymmetric xDSL',
  'Symmetric xDSL',
  'Other Wireline',
  'Cable Modem',
  'Optical Carrier',
  'Satellite',
  'Terrestrial Fixed Wireless',
  'Terrestrial Mobile Wireless',
  'Electric Power Line',
  'Other Technology',
);

@part2aoption = (
 'LD carrier',
 'owned loops',
 'unswitched UNE loops',
 'UNE-P',
 'UNE-P replacement',
 'FTTP',
 'coax',
 'wireless',
);

@part2boption = (
 'nomadic',
 'copper',
 'FTTP',
 'coax',
 'wireless',
 'other broadband',
);

#from the select at http://www.ffiec.gov/census/default.aspx
%states = (
  '01' => 'ALABAMA (AL)',
  '02' => 'ALASKA (AK)',
  '04' => 'ARIZONA (AZ)',
  '05' => 'ARKANSAS (AR)',
  '06' => 'CALIFORNIA (CA)',
  '08' => 'COLORADO (CO)',

  '09' => 'CONNECTICUT (CT)',
  '10' => 'DELAWARE (DE)',
  '11' => 'DISTRICT OF COLUMBIA (DC)',
  '12' => 'FLORIDA (FL)',
  '13' => 'GEORGIA (GA)',
  '15' => 'HAWAII (HI)',

  '16' => 'IDAHO (ID)',
  '17' => 'ILLINOIS (IL)',
  '18' => 'INDIANA (IN)',
  '19' => 'IOWA (IA)',
  '20' => 'KANSAS (KS)',
  '21' => 'KENTUCKY (KY)',

  '22' => 'LOUISIANA (LA)',
  '23' => 'MAINE (ME)',
  '24' => 'MARYLAND (MD)',
  '25' => 'MASSACHUSETTS (MA)',
  '26' => 'MICHIGAN (MI)',
  '27' => 'MINNESOTA (MN)',

  '28' => 'MISSISSIPPI (MS)',
  '29' => 'MISSOURI (MO)',
  '30' => 'MONTANA (MT)',
  '31' => 'NEBRASKA (NE)',
  '32' => 'NEVADA (NV)',
  '33' => 'NEW HAMPSHIRE (NH)',

  '34' => 'NEW JERSEY (NJ)',
  '35' => 'NEW MEXICO (NM)',
  '36' => 'NEW YORK (NY)',
  '37' => 'NORTH CAROLINA (NC)',
  '38' => 'NORTH DAKOTA (ND)',
  '39' => 'OHIO (OH)',

  '40' => 'OKLAHOMA (OK)',
  '41' => 'OREGON (OR)',
  '42' => 'PENNSYLVANIA (PA)',
  '44' => 'RHODE ISLAND (RI)',
  '45' => 'SOUTH CAROLINA (SC)',
  '46' => 'SOUTH DAKOTA (SD)',

  '47' => 'TENNESSEE (TN)',
  '48' => 'TEXAS (TX)',
  '49' => 'UTAH (UT)',
  '50' => 'VERMONT (VT)',
  '51' => 'VIRGINIA (VA)',
  '53' => 'WASHINGTON (WA)',

  '54' => 'WEST VIRGINIA (WV)',
  '55' => 'WISCONSIN (WI)',
  '56' => 'WYOMING (WY)',
  '72' => 'PUERTO RICO (PR)',
);

sub restore_fcc477map {
  my $key = shift;
  FS::Record::scalar_sql('',"select formvalue from fcc477map where formkey = ?",$key);
}

sub save_fcc477map {
  my $key = shift;
  my $value = shift;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  # lame (should be normal FS::Record access)

  my $sql = "delete from fcc477map where formkey = ?";
  my $sth = dbh->prepare($sql) or die dbh->errstr;
  $sth->execute($key) or do {
    warn "WARNING: Error removing FCC 477 form defaults: " . $sth->errstr;
    $dbh->rollback if $oldAutoCommit;
  };

  $sql = "insert into fcc477map (formkey,formvalue) values (?,?)";
  $sth = dbh->prepare($sql) or die dbh->errstr;
  $sth->execute($key,$value) or do {
    warn "WARNING: Error setting FCC 477 form defaults: " . $sth->errstr;
    $dbh->rollback if $oldAutoCommit;
  };

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;

  '';
}

sub parse_technology_option {
  my $cgi = shift;
  my $save = shift;
  my @result = ();
  my $i = 0;
  for (my $i = 0; $i < scalar(@technology); $i++) {
    my $value = $cgi->param("part1_technology_option_$i"); #lame
    save_fcc477map("part1_technology_option_$i",$value) 
        if $save && $value =~ /^\d+$/;
    push @result, $value =~ /^\d+$/ ? $value : 0;
  }
  return (@result);
}

sub statenum2state {
  my $num = shift;
  $states{$num};
}

sub join_optionnames {
  join(' ', map { join_optionname($_) } @_);
}

sub join_optionname {
  # Returns a FROM phrase to join a specific option into the query (via 
  # part_pkg).  The option value will appear as a field with the same name
  # as the option.
  my $name = shift;
  "LEFT JOIN (SELECT pkgpart, optionvalue AS $name FROM part_pkg_fcc_option".
    " WHERE fccoptionname = '$name') AS t_$name".
    " ON (part_pkg.pkgpart = t_$name.pkgpart)";
}

sub active_on {
  # Returns a condition to limit packages to those that were setup before a 
  # certain date, and not canceled before that date.
  #
  # (Strictly speaking this should also exclude suspended packages but 
  # "suspended as of some past date" is a complicated query.)
  my $date = shift;
  "cust_pkg.setup <= $date AND ".
  "(cust_pkg.cancel IS NULL OR cust_pkg.cancel > $date)";
}

sub is_fixed_broadband {
  "is_broadband = '1' AND technology::integer IN(".join(',',
    10, 11, 12, 20, 30, 40, 41, 42, 50, 60, 70, 90, 0
  ).")";
}

=item part6 OPTIONS

Returns Part 6 of the 2014 FCC 477 data, as an arrayref of arrayrefs.
OPTIONS may contain "date" => a timestamp to run the report as of that
date.

=cut

sub part6 {
  my $class = shift;
  my %opt = shift;
  my $date = $opt{date} || time;

  my @select = (
    'cust_location.censustract',
    'technology',
    'broadband_downstream',
    'broadband_upstream',
    'COUNT(*)',
    'COUNT(is_consumer)',
  );
  my $from =
    'cust_pkg
      JOIN cust_location USING (locationnum)
      JOIN part_pkg USING (pkgpart) '.
      join_optionnames(qw(
        is_broadband technology 
        broadband_downstream broadband_upstream
        is_consumer
        ))
  ;
  my @where = (
    active_on($date),
    is_fixed_broadband()
  );
  my $group_by = 'cust_location.censustract, technology, '.
                   'broadband_downstream, broadband_upstream ';
  my $order_by = $group_by;

  my $statement = "SELECT ".join(', ', @select) . "
  FROM $from
  WHERE ".join(' AND ', @where)."
  GROUP BY $group_by
  ORDER BY $order_by
  ";

  warn $statement if $DEBUG;
  dbh->selectall_arrayref($statement);
}

=item part9 OPTIONS

Returns Part 9 of the 2014 FCC 477 data, as above.

=cut

sub part9 {
  my $class = shift;
  my %opt = shift;
  my $date = $opt{date} || time;

  my @select = (
    "cust_location.state",
    "SUM(COALESCE(phone_vges::int,0))",
    "SUM(COALESCE(phone_circuits::int,0))",
    "SUM(COALESCE(phone_lines::int,0))",
    "SUM(CASE WHEN is_broadband = '1' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN is_consumer = '1' AND is_longdistance IS NULL THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN is_consumer = '1' AND is_longdistance = '1' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN is_consumer IS NULL AND is_longdistance IS NULL THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN is_consumer IS NULL AND is_longdistance = '1' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN phone_localloop = 'owned' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN phone_localloop = 'leased' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN phone_localloop = 'resale' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN media = 'Fiber' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN media = 'Cable Modem' THEN phone_lines::int ELSE 0 END)",
    "SUM(CASE WHEN media = 'Fixed Wireless' THEN phone_lines::int ELSE 0 END)",
  );
  my $from =
    'cust_pkg
      JOIN cust_location USING (locationnum)
      JOIN part_pkg USING (pkgpart) '.
      join_optionnames(qw(
        is_phone is_broadband media
        phone_vges phone_circuits phone_lines
        is_consumer is_longdistance phone_localloop 
        ))
  ;
  my @where = (
    active_on($date),
    "is_phone::int = 1",
  );
  my $group_by = 'cust_location.state';
  my $order_by = $group_by;

  my $statement = "SELECT ".join(', ', @select) . "
  FROM $from
  WHERE ".join(' AND ', @where)."
  GROUP BY $group_by
  ORDER BY $order_by
  ";

  warn $statement if $DEBUG;
  dbh->selectall_arrayref($statement);
}


1;
