<& elements/svc_Common.html,
              'table'     => 'svc_phone',
              'fields'    => \@fields,
              'labels'    => \%labels,
              'html_foot' => $html_foot,
&>
<%init>

my $conf = new FS::Conf;
my $countrydefault = $conf->config('countrydefault') || 'US';

my $fields = FS::svc_phone->table_info->{'fields'};
my %labels = map { $_ =>  ( ref($fields->{$_})
                             ? $fields->{$_}{'label'}
                             : $fields->{$_}
                         );
                 } keys %$fields;

my @fields = qw( countrycode phonenum sim_imsi );
push @fields, 'domain' if $conf->exists('svc_phone-domain');
push @fields, qw( pbx_title );

if ( $conf->exists('showpasswords') ) {
  push @fields, qw( sip_password );
} else {
  push @fields, { 'field' => 'sip_password', #'_HIDDEN_sip_password',
                  'type'  => 'fixed',
                  'value' => '<I>('. mt('hidden') .')</I>',
                };
}

push @fields, qw( pin phone_name forwarddst email );

push @fields, { field => 'sms_carrierid', 
                #type=>'cdr_carrier',
                value_callback => sub {
                  $_[0]->sms_carriername,
                },
              },
              'sms_account',
              'max_simultaneous',
;

if ( $conf->exists('svc_phone-lnp') ) {
  push @fields, 'lnp_status',
                'lnp_reject_reason',
                { field => 'portable', type => 'checkbox', },
                'lrn',
                { field => 'lnp_desired_due_date', type => 'date', },
                { field => 'lnp_due_date', type => 'date', },
                'lnp_other_provider',
                'lnp_other_provider_account',
  ;
}

$labels{circuit_label} = mt('Circuit');
push @fields, { field => 'circuit_label',
                link => [ $p.'view/svc_circuit.html?', 'circuit_svcnum' ]
              };

my $html_foot = sub {
  my $svc_phone = shift;

  ###
  # E911 Info
  ###

  my $e911 = 
    emt('E911 Information').
    &ntable("#cccccc"). '<TR><TD>'. ntable("#cccccc",2).
      '<TR><TD>'.emt('Location').'</TD>'.
      '<TD BGCOLOR="#FFFFFF">'.
        $svc_phone->location_label( 'join_string'     => '<BR>',
                                    'double_space'    => ' &nbsp; ',
                                    'escape_function' => \&encode_entities,
                                    'countrydefault'  => $countrydefault,
                                  ).
      '</TD></TR>'.
    '</TABLE></TD></TR></TABLE>'.
    '<BR>'
  ;

  ###
  # Devices
  ###
  #remove this when svc_phone isa device_Common, as elements/svc_Common will display it
  my $devices = include('/view/elements/svc_devices.html',
                          'svc_x' => $svc_phone,
                          'table' => 'phone_device',
                       );

  my $status = include('/view/elements/svc_export_status.html', $svc_phone );

  ##
  # CDR links
  ##

  tie my %what, 'Tie::IxHash',
    'pending' => 'NULL',
    'billed'  => 'done',
    'skipped' => 'failed',
  ;

  my $number = $svc_phone->phonenum;
  $number = $svc_phone->countrycode. $number
    unless $svc_phone->countrycode eq '1';

  #src & charged party as per voip_cdr.pm
  #XXX handle toll free too

  my $search = "charged_party_or_src=";

  my $cust_pkg = $svc_phone->cust_svc->cust_pkg;

  if ( $cust_pkg ) {

    #XXX handle voip_inbound too

    my @part_pkg = grep { $_->plan eq 'voip_cdr' }
                        $cust_pkg->part_pkg->self_and_bill_linked;

    foreach my $prefix (grep $_, map $_->option('default_prefix'), @part_pkg) {
      $number .= ",$prefix$number";
    }

    $search = 'charged_party='
      unless !@part_pkg || grep { ! $_->option('disable_src',1) } @part_pkg;

  }

  $search .= $number;

  my @links = map {
    qq(<A HREF="${p}search/cdr.html?cdrbatchnum=__ALL__;$search;freesidestatus=$what{$_}">).
    "View $_ CDRs</A>";
  } keys(%what);

  my @ilinks = ( qq(<A HREF="${p}search/cdr.html?cdrbatchnum=__ALL__;dst=$number">).
                 'View incoming CDRs</A>' );

  ###
  # concatenate & return
  ###

  $e911.
  $devices.
  $status.
  join(' | ', @links ). '<BR>'.
  join(' | ', @ilinks). '<BR>';

};

</%init>
