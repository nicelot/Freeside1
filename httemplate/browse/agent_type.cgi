<& elements/browse.html,
     'title'              => 'Agent Types',
     'menubar'            => [ 'Agents' => "${p}browse/agent.cgi" ],
     'html_init'          => $html_init,
     'name'               => 'agent types',
     'disableable'        => 1,
     'disabled_statuspos' => 2,
     'query'              => { 'table'     => 'agent_type',
                               'hashref'   => {},
                               'order_by' => 'ORDER BY typenum', # atype?
                             },
     'count_query'        => $count_query,
     'header'             => [ '#',
                               'Agent Type',
                               'Packages',
                             ],
     'fields'             => [ 'typenum',
                               'atype',
                               $packages_sub,
                             ],
     'links'              => [ $link,
                               $link,
                               '',
                             ],
&>
<%init>

die "access denied"
  unless $FS::CurrentUser::CurrentUser->access_right('Configuration');

my $html_init = 
'Agent types define groups of packages that you can then assign to'.
' particular agents.<BR><BR>'.
qq!<A HREF="${p}edit/agent_type.cgi"><I>Add a new agent type</I></A><BR><BR>!;

my $count_query = 'SELECT COUNT(*) FROM agent_type';

#false laziness w/access_user.html
my $packages_sub = sub {
  my $agent_type = shift;
  my @type_pkgs = $agent_type->type_pkgs_enabled;
  return '(lots; edit agent type to view)' if scalar(@type_pkgs) > 32;

  [ map {
          my $type_pkgs = $_;
          #my $part_pkg = $type_pkgs->part_pkg;
          [
            {
              #'data'  => $part_pkg->pkg. ' - '. $part_pkg->comment,
              'data'  => encode_entities($type_pkgs->pkg). ' - '.
                         ( $type_pkgs->custom ? '(CUSTOM) ' : '' ).
                         encode_entities($type_pkgs->comment),
              'align' => 'left',
              'link'  => $p. 'edit/part_pkg.cgi?'. $type_pkgs->pkgpart,
            },
          ];
        }
      @type_pkgs
  ];

};

my $link = [ $p.'edit/agent_type.cgi?', 'typenum' ];

</%init>
