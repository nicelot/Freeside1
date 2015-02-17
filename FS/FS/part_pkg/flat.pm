package FS::part_pkg::flat;
use base qw( FS::part_pkg::prorate_Mixin
             FS::part_pkg::discount_Mixin
             FS::part_pkg
           );

use strict;
use vars qw( %info %usage_recharge_fields @usage_recharge_fieldorder );
use FS::Record qw( qsearch );
use Tie::IxHash;
use List::Util qw( min );
use FS::UI::bytecount;
use FS::Conf;

tie my %temporalities, 'Tie::IxHash',
  'upcoming'  => "Upcoming (future)",
  'preceding' => "Preceding (past)",
;

tie my %contract_years, 'Tie::IxHash', (
  '' => '(none)',
  map { $_*12 => $_ } (1..5),
);

%info = (
  'name' => 'Flat rate (anniversary billing)',
  'shortname' => 'Anniversary',
  'inherit_fields' => [ 'prorate_Mixin', 'usage_Mixin', 'global_Mixin' ],
  'fields' => {
    #false laziness w/voip_cdr.pm
    'recur_temporality' => { 'name' => 'Charge recurring fee for period',
                             'type' => 'select',
                             'select_options' => \%temporalities,
                           },

    #used in cust_pkg.pm so could add to any price plan
    'expire_months' => { 'name' => 'Auto-add an expiration date this number of months out',
                       },
    'adjourn_months'=> { 'name' => 'Auto-add a suspension date this number of months out',
                       },
    'contract_end_months'=> { 
                        'name' => 'Auto-add a contract end date this number of years out',
                        'type' => 'select',
                        'select_options' => \%contract_years,
                      },
    #used in cust_pkg.pm so could add to any price plan where it made sense
    'start_1st'     => { 'name' => 'Auto-add a start date to the 1st, ignoring the current month.',
                         'type' => 'checkbox',
                       },
    'sync_bill_date' => { 'name' => 'Prorate first month to synchronize '.
                                    'with the customer\'s other packages',
                          'type' => 'checkbox',
                        },
    'prorate_defer_bill' => { 
                          'name' => 'When synchronizing, defer the bill until '.
                                    'the customer\'s next bill date',
                          'type' => 'checkbox',
                        },
    'prorate_round_day' => {
                          'name' => 'When synchronizing, round the prorated '.
                                    'period to the nearest full day',
                          'type' => 'checkbox',
                        },
    'add_full_period' => { 'disabled' => 1 }, # doesn't make sense with sync?

    'suspend_bill' => { 'name' => 'Continue recurring billing while suspended',
                        'type' => 'checkbox',
                      },
    'unsuspend_adjust_bill' => 
                        { 'name' => 'Adjust next bill date forward when '.
                                    'unsuspending',
                          'type' => 'checkbox',
                        },
    'bill_recur_on_cancel' => {
                        'name' => 'Bill the last period on cancellation',
                        'type' => 'checkbox',
                        },
    'bill_suspend_as_cancel' => {
                        'name' => 'Bill immediately upon suspension', #desc?
                        'type' => 'checkbox',
                        },
    'externalid' => { 'name'   => 'Optional External ID',
                      'default' => '',
                    },
  },
  'fieldorder' => [ qw( recur_temporality 
                        expire_months adjourn_months
                        contract_end_months
                        start_1st
                        sync_bill_date prorate_defer_bill prorate_round_day
                        suspend_bill unsuspend_adjust_bill
                        bill_recur_on_cancel
                        bill_suspend_as_cancel
                        externalid ),
                  ],
  'weight' => 10,
);

sub price_info {
    my $self = shift;
    my %opt = @_;
    my $conf = new FS::Conf;
    my $money_char = $conf->config('money_char') || '$';
    my $setup = $opt{cust_pkg} ? $self->base_setup( $opt{cust_pkg} )
                               : ($self->option('setup_fee') || 0);
    my $recur = $opt{cust_pkg} ? $self->base_recur( $opt{cust_pkg} )
                               : ($self->option('recur_fee', 1) || 0);
    $recur += $self->usageprice_recur( $opt{cust_pkg} ) if $opt{cust_pkg};
    my $str = '';
    $str = $money_char . $setup . ($recur ? ' setup' : ' one-time') if $setup;
    $str .= ', ' if ($setup && $recur);
    $str .= $money_char. $recur. '/'. $self->freq_pretty if $recur;
    $str;
}

sub calc_setup {
  my($self, $cust_pkg, $sdate, $details, $param ) = @_;

  return 0 if $self->prorate_setup($cust_pkg, $sdate);

  my $i = 0;
  my $count = $self->option( 'additional_count', 'quiet' ) || 0;
  while ($i < $count) {
    push @$details, $self->option( 'additional_info' . $i++ );
  }

  my $charge = $self->base_setup($cust_pkg, $sdate, $details);

  my $discount = 0;
  if ( $charge > 0 ) {
      $param->{'setup_charge'} = $charge;
      $discount = $self->calc_discount($cust_pkg, $sdate, $details, $param);
      delete $param->{'setup_charge'};
  }

  sprintf( '%.2f', ($cust_pkg->quantity || 1) * ($charge - $discount) );
}

sub base_setup {
  my($self, $cust_pkg, $sdate, $details ) = @_;

  $self->option('setup_fee') || 0;
}

sub calc_recur {
  my $self = shift;
  my($cust_pkg, $sdate, $details, $param ) = @_;

  #my $last_bill = $cust_pkg->last_bill;
  my $last_bill = $cust_pkg->get('last_bill'); #->last_bill falls back to setup

  return 0
    if $self->recur_temporality eq 'preceding' && !$last_bill;

  my $charge = $self->base_recur($cust_pkg, $sdate);
  # always treat cutoff_day as a list
  if ( my @cutoff_day = $self->cutoff_day($cust_pkg) ) {
    $charge = $self->calc_prorate(@_, @cutoff_day);
  }
  elsif ( $param->{freq_override} ) {
    # XXX not sure if this should be mutually exclusive with sync_bill_date.
    # Given the very specific problem that freq_override is meant to 'solve',
    # it probably should.
    $charge *= $param->{freq_override} if $param->{freq_override};
  }

  $charge += $self->usageprice_recur($cust_pkg, $sdate);
  $cust_pkg->apply_usageprice(); #$sdate for prorating?

  my $discount = $self->calc_discount($cust_pkg, $sdate, $details, $param);

  sprintf( '%.2f', ($cust_pkg->quantity || 1) * ($charge - $discount) );
}

sub cutoff_day {
  my $self = shift;
  my $cust_pkg = shift;
  if ( $self->option('sync_bill_date',1) ) {
    my $next_bill = $cust_pkg->cust_main->next_bill_date;
    if ( defined($next_bill) ) {
      return (localtime($next_bill))[3];
    }
  }
  return ();
}

sub base_recur {
  my($self, $cust_pkg, $sdate) = @_;
  $self->option('recur_fee', 1) || 0;
}

sub base_recur_permonth {
  my($self, $cust_pkg) = @_;

  return 0 unless $self->freq =~ /^\d+$/ && $self->freq > 0;

  sprintf('%.2f', $self->base_recur($cust_pkg) / $self->freq );
}

sub usageprice_recur {
  my($self, $cust_pkg, $sdate) = @_;

  my $recur = 0;
  $recur += $_->price foreach $cust_pkg->cust_pkg_usageprice;

  sprintf('%.2f', $recur);
}

sub calc_cancel {
  my $self = shift;
  my $conf = new FS::Conf;
  if ( $self->recur_temporality eq 'preceding'
       and $self->option('bill_recur_on_cancel', 1) ) {
    # run another recurring cycle
    return $self->calc_recur(@_);
  }
  elsif ( $conf->exists('bill_usage_on_cancel') # should be a package option?
          and $self->can('calc_usage') ) {
    # bill for outstanding usage
    return $self->calc_usage(@_);
  }
  0;
}

sub calc_remain {
  my ($self, $cust_pkg, %options) = @_;

  my $time;
  if ($options{'time'}) {
    $time = $options{'time'};
  } else {
    $time = time;
  }

  my $next_bill = $cust_pkg->getfield('bill') || 0;

  return 0 if    ! $self->base_recur($cust_pkg, \$time)
              || ! $next_bill
              || $next_bill < $time;

  # Use actual charge for this period, not base_recur (for discounts).
  # Use sdate < $time and edate >= $time because when billing on 
  # cancellation, edate = $time.
  my $credit = 0;
  foreach my $item ( 
    qsearch('cust_bill_pkg', { 
      pkgnum => $cust_pkg->pkgnum,
      sdate => {op => '<' , value => $time},
      edate => {op => '>=', value => $time},
      recur => {op => '>' , value => 0},
    })
  ) {
    # hack to deal with the weird behavior of edate on package cancellation
    my $edate = $item->edate;
    if ( $self->recur_temporality eq 'preceding' ) {
      $edate = $self->add_freq($item->sdate);
    }
    $credit += ($item->recur - $item->usage) * 
               ($edate - $time) / ($edate - $item->sdate);
  } 
  sprintf('%.2f', $credit);
  #sprintf("%.2f", $self->base_recur($cust_pkg, \$time) * ( $next_bill - $time ) / $freq_sec );

}

sub is_free_options {
  qw( setup_fee recur_fee );
}

sub is_prepaid { 0; } #no, we're postpaid

sub can_start_date {
  my $self = shift;
  my %opt = @_;
  return 0 if $self->start_on_hold;

  ! $self->option('start_1st', 1) && (   ! $self->option('sync_bill_date',1)
                                      || ! $self->option('prorate_defer_bill',1)
                                      || ! $opt{'num_ncancelled_pkgs'}
                                     ); 
}

sub can_discount { 1; }

sub can_usageprice { 1; }

sub recur_temporality {
  my $self = shift;
  $self->option('recur_temporality', 1);
}

sub usage_valuehash {
  my $self = shift;
  map { $_, $self->option($_) }
    grep { $self->option($_, 'hush') } 
    qw(seconds upbytes downbytes totalbytes);
}

sub reset_usage {
  my($self, $cust_pkg, %opt) = @_;
  warn "   resetting usage counters" if defined($opt{debug}) && $opt{debug} > 1;
  my %values = $self->usage_valuehash;
  if ($self->option('usage_rollover', 1)) {
    $cust_pkg->recharge(\%values);
  }else{
    $cust_pkg->set_usage(\%values, %opt);
  }
}

1;
