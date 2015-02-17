% if ( scalar(@cust_main) == 1 && ! $cgi->param('referral_custnum') ) {
%  if ( $cgi->param('quickpay') eq 'yes' ) {
    <% $cgi->redirect(popurl(2). "edit/cust_pay.cgi?quickpay=yes;custnum=". $cust_main[0]->custnum) %>
%  } else {
    <% $cgi->redirect(popurl(2). "view/cust_main.cgi?". $cust_main[0]->custnum) %>
%  }
%} elsif ( scalar(@cust_main) == 0 ) {
%  errorpage(emt("No matching customers found!"));
% } # errorpage quits, so we don't need an 'else' below

<& /elements/header.html, mt("Customer Search Results"), '' &>
% $total ||= scalar(@cust_main); 

<% mt("[_1] matching customers found",$total) |h %>

% my $pager = include( '/elements/pager.html',
%                        'offset'     => $offset,
%            'num_rows'   => scalar(@cust_main),
%            'total'      => $total,
%            'maxrecords' => $maxrecords,
%                    );

%  unless ( $cgi->param('cancelled') ) {
%    my $linklabel = '';
%    if ( $cgi->param('showcancelledcustomers') eq '0' #see if it was set by me
%         || ( $conf->exists('hidecancelledcustomers')
%              && ! $cgi->param('showcancelledcustomers')
%            )
%       ) {
%      $cgi->param('showcancelledcustomers', 1);
%      $linklabel = 'show';
%    } else {
%      $cgi->param('showcancelledcustomers', 0);
%      $linklabel = 'hide';
%    }
%    $cgi->param('offset', 0);
        ( <a href="<% $cgi->self_url %>"><% mt("$linklabel canceled customers") |h %></a> )
%  }

%  if ( $cgi->param('referral_custnum') ) {
%    $cgi->param('referral_custnum') =~ /^(\d+)$/
%      or errorpage(emt("Illegal referral_custnum"));
%    my $referral_custnum = $1;
%    my $cust_main = qsearchs('cust_main', { custnum => $referral_custnum } );
    <SCRIPT>
        function changed(what) {
            what.form.submit();
        }
    </SCRIPT>

% # XXX: translate this section...hard due to "referrals of CUST SELECT levels deep" construction
    <FORM METHOD="GET">
        <INPUT TYPE="hidden" NAME="referral_custnum" VALUE="<% $referral_custnum %>">
%   my $refcustlabel = "$referral_custnum: " .
%         ( $cust_main->company || $cust_main->last. ', '. $cust_main->first );
        referrals of
        <A HREF="<% popurl(2)."view/cust_main.cgi?$referral_custnum" %>"><% $refcustlabel |h %></A>
        <SELECT NAME="referral_depth" SIZE="1" onChange="changed(this)">';

%    my $max = 8;
%    $cgi->param('referral_depth') =~ /^(\d*)$/ 
%      or errorpage(emt("Illegal referral_depth"));
%    my $referral_depth = $1;

%    foreach my $depth ( 1 .. $max ) {
%       my $selected = ($depth == $referral_depth) ? 'SELECTED' : '';
        <OPTION <% $selected %>><% $depth %>
%    }
    </SELECT> levels deep
    </FORM>
%  }

%  my @custom_priorities = ();
%  if ( $conf->config('ticket_system-custom_priority_field')
%       && @{[ $conf->config('ticket_system-custom_priority_field-values') ]} ) {
%    @custom_priorities =
%      $conf->config('ticket_system-custom_priority_field-values');
%  }

  <BR><BR><% $pager.include('/elements/table-grid.html') %>
      <TR>
        <TH CLASS="grid" BGCOLOR="#cccccc"><% mt('#') |h %></TH>
        <TH CLASS="grid" BGCOLOR="#cccccc"><% mt('Status') |h %></TH>
        <TH CLASS="grid" BGCOLOR="#cccccc"><% mt('Name') |h %></TH>
        <TH CLASS="grid" BGCOLOR="#cccccc"><% mt('Company') |h %></TH>

%foreach my $addl_header ( @addl_headers ) {
    <TH CLASS="grid" BGCOLOR="#cccccc"><% $addl_header %></TH>
%}

        <TH CLASS="grid" BGCOLOR="#cccccc"><% mt('Packages') |h %></TH>
        <TH CLASS="grid" BGCOLOR="#cccccc" COLSPAN="2"><% mt('Services') |h %></TH>
     </TR>

%  my $bgcolor1 = '#eeeeee';
%  my $bgcolor2 = '#ffffff';
%  my $bgcolor;
%
%  my(%saw,$cust_main);
%  foreach $cust_main (
%    sort $sortby grep(!$saw{$_->custnum}++, @cust_main)
%  ) {
%
%    if ( $bgcolor eq $bgcolor1 ) {
%      $bgcolor = $bgcolor2;
%    } else {
%      $bgcolor = $bgcolor1;
%    }
%
%    my($custnum,$last,$first,$company)=(
%      $cust_main->custnum,
%      $cust_main->getfield('last'),
%      $cust_main->getfield('first'),
%      $cust_main->company,
%    );
%
%    my @all_cust_svc;
%    my @pkg_rowspans;
%    foreach my $cust_pkg ( @{$all_pkgs{$custnum}} ) {
%      my %cust_svc_by_svcpart;
%      my $rows = 0;
%      foreach my $part_svc ( $cust_pkg->part_svc ) {
%        my $svcpart = $part_svc->svcpart;
%        my $num_cust_svc = $cust_pkg->num_cust_svc($svcpart);
%        if ( $large_pkg_size > 0 and $num_cust_svc >= $large_pkg_size ) {
%          # don't retrieve the cust_svc records, just stash the 
%          # part_svc and num_cust_svc for later
%          $cust_svc_by_svcpart{$svcpart} = 
%            [ 'summarize', $part_svc, $num_cust_svc ];
%          $rows += 2;
%        }
%        elsif ( $num_cust_svc ) {
%          $cust_svc_by_svcpart{$svcpart} = [ $cust_pkg->cust_svc($svcpart) ];
%          $rows += $num_cust_svc;
%        } #if summarize
%      } #foreach $part_svc
%      $rows ||= 1; # in case the package has no services
%      push @all_cust_svc, \%cust_svc_by_svcpart;
%      push @pkg_rowspans, $rows;
%    } #foreach $cust_pkg
%    my $rowspan = List::Util::sum(@pkg_rowspans) || 1;
%
%    my $view;
%    if ( defined $cgi->param('quickpay') && $cgi->param('quickpay') eq 'yes' ) {
%      $view = $p. 'edit/cust_pay.cgi?quickpay=yes;custnum='. $custnum;
%    } else {
%      $view = $p. 'view/cust_main.cgi?'. $custnum;
%    }
%    my $pcompany = $company
%      ? qq!<A HREF="$view"><FONT SIZE=-1>!. encode_entities($company). '</FONT></A>'
%      : '<FONT SIZE=-1>&nbsp;</FONT>';
%    
%    my $status_label = $cust_main->status_label;
%    my $statuscolor = $cust_main->statuscolor;

    <TR>
      <TD CLASS="grid" ALIGN="right" BGCOLOR="<% $bgcolor %>" ROWSPAN=<% $rowspan %>>
        <A HREF="<% $view %>"><FONT SIZE=-1><% $cust_main->display_custnum %></FONT></A>
      </TD>
      <TD CLASS="grid" ALIGN="center" BGCOLOR="<% $bgcolor %>" ROWSPAN=<% $rowspan %>>
        <FONT SIZE="-1" COLOR="#<% $statuscolor %>"><B><% $status_label %></B></FONT>
      </TD>
      <TD CLASS="grid" BGCOLOR="<% $bgcolor %>" ROWSPAN=<% $rowspan %>>
        <A HREF="<% $view %>"><FONT SIZE=-1><% "$last, $first" |h %></FONT></A>
      </TD>
      <TD CLASS="grid" BGCOLOR="<% $bgcolor %>" ROWSPAN=<% $rowspan %>>
        <% $pcompany %>
      </TD>

%    foreach my $addl_col ( @addl_cols ) { 
% if ( $addl_col eq 'tickets' ) { 
% if ( @custom_priorities ) { 

        <TD CLASS="inv" BGCOLOR="<% $bgcolor %>" ROWSPAN=<% $rowspan %> ALIGN=right>
            <FONT SIZE=-1>
               <TABLE CLASS="inv" CELLSPACING=0 CELLPADDING=0>
% foreach my $priority ( @custom_priorities, '' ) { 
%                    my $num =
%                      FS::TicketSystem->num_customer_tickets($custnum,$priority);
%                    my $ahref = '';
%                    $ahref= '<A HREF="'.
%                            FS::TicketSystem->href_customer_tickets($custnum,$priority).
%                            '">'
%                      if $num;
        
                 <TR>
                   <TD ALIGN=right>
                     <FONT SIZE=-1><% $ahref.$num %></A></FONT>
                   </TD>
                   <TD ALIGN=left>
                     <FONT SIZE=-1><% $ahref %><% $priority || '<i>('.emt('none').')</i>' %></A></FONT>
                   </TD>
                 </TR>
% } 

             <TR>
               <TH ALIGN=right STYLE="border-top: dashed 1px black">
               <FONT SIZE=-1>
% } else { 
          <TD CLASS="grid" BGCOLOR="<% $bgcolor %>" ROWSPAN=<% $rowspan %> ALIGN=right>
            <FONT SIZE=-1>
% } 
%           my $ahref = '';
%           $ahref = '<A HREF="'.
%                       FS::TicketSystem->href_customer_tickets($custnum).
%                       '">'
%             if $cust_main->get($addl_col);
%        

        <% $ahref %><% $cust_main->get($addl_col) %></A>
% if ( @custom_priorities ) { 

          </FONT></TH>
            <TH ALIGN=left STYLE="border-top: dashed 1px black">
              <FONT SIZE=-1><% ${ahref} %>Total</A><FONT>
            </TH>
          </TR>
          </TABLE>
% } 

        </FONT></TD>
% } else { 

        <TD CLASS="grid" BGCOLOR="<% $bgcolor %>" ROWSPAN=<% $rowspan %> ALIGN=right><FONT SIZE=-1>
          <% $cust_main->get($addl_col) %>
        </FONT></TD>

%      }
%    }

%    my $n1 = '';
%    foreach ( @{$all_pkgs{$custnum}} ) {
%      my $pkgnum = $_->pkgnum;
%      my $part_pkg = $_->part_pkg;
%
%      my $pkg_comment = $part_pkg->pkg_comment( cust_pkg=>$_, nopkgpart=>1 );
%      my $show = $curuser->default_customer_view =~ /^(jumbo|packages)$/
%                   ? ''
%                   : ';show=packages';
%      my $frag = "cust_pkg$pkgnum"; #hack for IE ignoring real #fragment
%      my $pkgview = "${p}view/cust_main.cgi?custnum=$custnum$show;fragment=$frag#$frag";
%      # cust_svc stuff, built earlier
%      my %cust_svc_by_svcpart = %{ shift @all_cust_svc };
%      my $pkg_rowspan = shift @pkg_rowspans;

        <% $n1 %><TD CLASS="grid" BGCOLOR="<% $bgcolor %>"  ROWSPAN="<% $pkg_rowspan%>">
            <A HREF="<% $pkgview %>"><FONT SIZE=-1><% $pkg_comment |h %></FONT></A>
        </TD>

%       my $n2 = '';
%       my $td = '<TD CLASS="grid" BGCOLOR="'.$bgcolor.'">';
%
%       foreach my $svcpart ( sort keys %cust_svc_by_svcpart ) { #sort order?
%         my $these = $cust_svc_by_svcpart{$svcpart};
%         if ( $these->[0] eq 'summarize' ) {
%           my $part_svc = $these->[1];
%           my $num_cust_svc = $these->[2];
        <% $n2 %>
%           # summarize
%           # link opens a new search for this pkgnum/svcpart combo
%           my $href = $p.'search/cust_pkg_svc.html?svcpart='.$svcpart.
%                     ';pkgnum='.$pkgnum;
          <% $td %>
            <A HREF="<% $href %>"><% $part_svc->svc %></A>
          </TD>
          <% $td %>
            <A HREF="<% $href %>"><B>(<% mt("view all [_1]", $num_cust_svc) |h %>)</B></A>
          </TD>
        </TR><TR>
          <% $td %></TD>
          <% $td %><& /elements/search-cust_svc.html, 
                    'svcpart' => $svcpart,
                    'pkgnum'  => $pkgnum,
                    'svcdb'   => $part_svc->svcdb,
                    &></TD>
%           $n2="</TR><TR>";
%         }
%         elsif ( scalar @$these ) { # do not summarize
%           foreach my $cust_svc ( @$these ) {
          <% $n2 %>
            <% $td %>
                <% FS::UI::Web::svc_link($m, $cust_svc->part_svc, $cust_svc) %>
            </TD> 
            <% $td %>
                <% FS::UI::Web::svc_label_link($m, $cust_svc->part_svc, $cust_svc) %>
            </TD>
%             $n2="</TR><TR>";
%           } #foreach $cust_svc
%         }
%       } # foreach $svcpart
%
%      unless ( %cust_svc_by_svcpart ) {
            <TD CLASS="grid" BGCOLOR="<% $bgcolor %>" COLSPAN=2>&nbsp;</TD>
%      }
%
%      $n1="</TR><TR>";
%    }
%
%    unless ( @{$all_pkgs{$custnum}} ) {
        <TD CLASS="grid" BGCOLOR="<% $bgcolor %>" COLSPAN=3>&nbsp;</TD>
%    }
%    
    </TR>
%  }
 
  </TABLE><% $pager %>

  <& /elements/footer.html &>
<%init>
my $curuser = $FS::CurrentUser::CurrentUser;

die "access denied"
  unless $curuser->access_right('List all customers');

my $conf = new FS::Conf;
my $maxrecords = $conf->config('maxsearchrecordsperpage');
# summarize more than this many services of the same svcpart
my $large_pkg_size = $conf->config('cust_pkg-large_pkg_size') || 0;

my $limit = '';
$limit .= "LIMIT $maxrecords" if $maxrecords;

my $offset = $cgi->param('offset') || 0;
$limit .= " OFFSET $offset" if $offset;

my $total = 0;

my(@cust_main, $sortby, $orderby);
my @select = ();
my @addl_headers = ();
my @addl_cols = ();
if ( $cgi->param('browse')
     || $cgi->param('otaker_on')
     || $cgi->param('agentnum_on')
) {

  my %search = ();

  if ( $cgi->param('browse') ) {
    my $query = $cgi->param('browse');
    if ( $query eq 'custnum' ) {
      if ( $conf->exists('cust_main-default_agent_custid') ) {
        $sortby=\*display_custnum_sort;
        $orderby = "ORDER BY CASE WHEN agent_custid IS NOT NULL AND agent_custid != '' THEN CAST(agent_custid AS BIGINT) ELSE custnum END";
      } else {
        $sortby=\*custnum_sort;
        $orderby = "ORDER BY custnum";
      }
    } elsif ( $query eq 'last' ) {
      $sortby=\*last_sort;
      $orderby = "ORDER BY LOWER(last || ' ' || first)";
    } elsif ( $query eq 'company' ) {
      $sortby=\*company_sort;
      $orderby = "ORDER BY LOWER(company || ' ' || last || ' ' || first )";
    } elsif ( $query eq 'tickets' ) {
      $sortby = \*tickets_sort;
      $orderby = "ORDER BY tickets DESC";
      push @select, FS::TicketSystem->sql_num_customer_tickets. " as tickets";
      push @addl_headers, 'Tickets';
      push @addl_cols, 'tickets';
    } elsif ( $query eq 'uspsunvalid' ) {
       $search{'country'} = 'US';
       $sortby=\*custnum_sort;
       $orderby = "ORDER BY custnum";
    } else {
      die "unknown browse field $query";
    }
  } else {
    $sortby = \*last_sort; #??
    $orderby = "ORDER BY LOWER(last || ' ' || first)"; #??
  }

  if ( $cgi->param('otaker_on') ) {
    die "access denied"
      unless $FS::CurrentUser::CurrentUser->access_right('Configuration');
    $cgi->param('otaker') =~ /^(\w{1,32})$/ or errorpage("Illegal otaker");
    $search{otaker} = $1;
  } elsif ( $cgi->param('agentnum_on') ) {
    $cgi->param('agentnum') =~ /^(\d+)$/ or errorpage("Illegal agentnum");
    $search{agentnum} = $1;
  }

  my @qual = ();

  my $ncancelled = '';

  if (  $cgi->param('showcancelledcustomers') eq '0' #see if it was set by me
       || ( $conf->exists('hidecancelledcustomers')
             && ! $cgi->param('showcancelledcustomers') )
     ) {
    push @qual, FS::cust_main->uncancel_sql;
   }

  push @qual, FS::cust_main->cancel_sql   if $cgi->param('cancelled');
  push @qual, FS::cust_main->prospect_sql if $cgi->param('prospect');
  push @qual, FS::cust_main->ordered_sql  if $cgi->param('ordered');
  push @qual, FS::cust_main->active_sql   if $cgi->param('active');
  push @qual, FS::cust_main->inactive_sql if $cgi->param('inactive');
  push @qual, FS::cust_main->susp_sql     if $cgi->param('suspended');

  #EWWWWWW
  my $qual = join(' AND ',
            map { "$_ = ". dbh->quote($search{$_}) } keys %search );

  my $addl_qual = join(' AND ', @qual);

  #here is the agent virtualization
  $addl_qual .= ( $addl_qual ? ' AND ' : '' ).
                $FS::CurrentUser::CurrentUser->agentnums_sql;

  if ( $cgi->param('browse') && $cgi->param('browse') eq 'uspsunvalid' ) {
       $addl_qual .= ' AND ( length(zip) < 9 OR upper(address1) != address1 OR upper(city) != city ) ';
  }

  if ( $addl_qual ) {
    $qual .= ' AND ' if $qual;
    $qual .= $addl_qual;
  }
    
  $qual = " WHERE $qual" if $qual;
  my $statement = "SELECT COUNT(*) FROM cust_main $qual";
  my $sth = dbh->prepare($statement) or die dbh->errstr." preparing $statement";
  $sth->execute or die "Error executing \"$statement\": ". $sth->errstr;

  $total = $sth->fetchrow_arrayref->[0];

  if ( $addl_qual ) {
    if ( %search ) {
      $addl_qual = " AND $addl_qual";
    } else {
      $addl_qual = " WHERE $addl_qual";
    }
  }

  my $select;
  if ( @select ) {
    $select = 'cust_main.*, '. join (', ', @select);
  } else {
    $select = '*';
  }

  @cust_main = qsearch('cust_main', \%search, $select,   
                         "$addl_qual $orderby $limit" );

} else {
  @cust_main=();
  $sortby = \*last_sort;

  push @cust_main, @{&custnumsearch}
    if $cgi->param('custnum_on') && $cgi->param('custnum_text');
  push @cust_main, @{&cardsearch}
    if $cgi->param('card_on') && $cgi->param('card');
  push @cust_main, @{&lastsearch}
    if $cgi->param('last_on') && $cgi->param('last_text');
  push @cust_main, @{&companysearch}
    if $cgi->param('company_on') && $cgi->param('company_text');
  push @cust_main, @{&address2search}
    if $cgi->param('address2_on') && $cgi->param('address2_text');
  push @cust_main, @{&phonesearch}
    if $cgi->param('phone_on') && $cgi->param('phone_text');
  push @cust_main, @{&referralsearch}
    if $cgi->param('referral_custnum');

  if ( $cgi->param('company_on') && $cgi->param('company_text') ) {
    $sortby = \*company_sort;
    push @cust_main, @{&companysearch};
  }

  if ( $cgi->param('search_cust') ) {
    $sortby = \*company_sort;
    $orderby = "ORDER BY LOWER(company || ' ' || last || ' ' || first )";
    push @cust_main, smart_search(
      'search'            => scalar($cgi->param('search_cust')),
      'no_fuzzy_on_exact' => ! ( $curuser->option('enable_fuzzy_on_exact')
                                 || $conf->exists('enable_fuzzy_on_exact')
                               ),
    );
  }

  @cust_main = grep { $_->ncancelled_pkgs || ! $_->all_pkgs } @cust_main
    if ! $cgi->param('cancelled')
       && (
         $cgi->param('showcancelledcustomers') eq '0' #see if it was set by me
         || ( $conf->exists('hidecancelledcustomers')
               && ! $cgi->param('showcancelledcustomers') )
       );

  my %saw = ();
  @cust_main = grep { !$saw{$_->custnum}++ } @cust_main;
}

my %all_pkgs;
if ( $conf->exists('hidecancelledpackages' ) ) {
  %all_pkgs = map { $_->custnum => [ $_->ncancelled_pkgs ] } @cust_main;
} else {
  %all_pkgs = map { $_->custnum => [ $_->all_pkgs ] } @cust_main;
}

sub last_sort {
  lc($a->getfield('last')) cmp lc($b->getfield('last'))
  || lc($a->first) cmp lc($b->first);
}

sub company_sort {
  return -1 if $a->company && ! $b->company;
  return 1 if ! $a->company && $b->company;
  lc($a->company) cmp lc($b->company)
  || lc($a->getfield('last')) cmp lc($b->getfield('last'))
  || lc($a->first) cmp lc($b->first);;
}

sub display_custnum_sort {
  $a->display_custnum <=> $b->display_custnum;
}

sub custnum_sort {
  $a->getfield('custnum') <=> $b->getfield('custnum');
}

sub tickets_sort {
  $b->getfield('tickets') <=> $a->getfield('tickets');
}

sub custnumsearch {

  my $custnum = $cgi->param('custnum_text');
  $custnum =~ s/\D//g;
  $custnum =~ /^(\d{1,23})$/ or errorpage(emt("Illegal customer number"));
  $custnum = $1;
  
  [ qsearchs('cust_main', { 'custnum' => $custnum } ) ];
}

sub cardsearch {

  my($card)=$cgi->param('card');
  $card =~ s/\D//g;
  $card =~ /^(\d{13,16}|\d{8,9})$/ or errorpage(emt("Illegal card number"));
  my($payinfo)=$1;

  [ qsearch('cust_main',{'payinfo'=>$payinfo, 'payby'=>'CARD'}),
    qsearch('cust_main',{'payinfo'=>$payinfo, 'payby'=>'DCRD'})
  ];
}

sub referralsearch {
  $cgi->param('referral_custnum') =~ /^(\d+)$/
    or errorpage("Illegal referral_custnum");
  my $cust_main = qsearchs('cust_main', { 'custnum' => $1 } )
    or errorpage(emt("Customer [_1] not found",$1));
  my $depth;
  if ( $cgi->param('referral_depth') ) {
    $cgi->param('referral_depth') =~ /^(\d+)$/
      or errorpage(emt("Illegal referral_depth"));
    $depth = $1;
  } else {
    $depth = 1;
  }
  [ $cust_main->referral_cust_main($depth) ];
}

sub lastsearch {
  my(%last_type);
  my @cust_main;
  foreach ( $cgi->param('last_type') ) {
    $last_type{$_}++;
  }

  $cgi->param('last_text') =~ /^([\w \,\.\-\']*)$/
    or errorpage(emt("Illegal last name"));
  my($last)=$1;

  if ( $last_type{'Exact'} || $last_type{'Fuzzy'} ) {
    push @cust_main, qsearch( 'cust_main',
                              { 'last' => { 'op'    => 'ILIKE',
                                            'value' => $last    } } );

    push @cust_main, qsearch( 'cust_main',
                              { 'ship_last' => { 'op'    => 'ILIKE',
                                                 'value' => $last    } } )
      if defined dbdef->table('cust_main')->column('ship_last');
  }

  if ( $last_type{'Substring'} || $last_type{'All'} ) {

    push @cust_main, qsearch( 'cust_main',
                              { 'last' => { 'op'    => 'ILIKE',
                                            'value' => "%$last%" } } );

    push @cust_main, qsearch( 'cust_main',
                              { 'ship_last' => { 'op'    => 'ILIKE',
                                                 'value' => "%$last%" } } )
      if defined dbdef->table('cust_main')->column('ship_last');

  }

  if ( $last_type{'Fuzzy'} || $last_type{'All'} ) {
    push @cust_main, FS::cust_main::Search->fuzzy_search( { 'last' => $last } );
  }

  \@cust_main;
}

sub companysearch {

  my(%company_type);
  my @cust_main;
  foreach ( $cgi->param('company_type') ) {
    $company_type{$_}++ 
  };

  $cgi->param('company_text') =~
    /^([\w \!\@\#\$\%\&\(\)\-\+\;\:\'\"\,\.\?\/\=]*)$/
      or errorpage(emt("Illegal company"));
  my $company = $1;

  if ( $company_type{'Exact'} || $company_type{'Fuzzy'} ) {
    push @cust_main, qsearch( 'cust_main',
                              { 'company' => { 'op'    => 'ILIKE',
                                               'value' => $company } } );

    push @cust_main, qsearch( 'cust_main',
                              { 'ship_company' => { 'op'    => 'ILIKE',
                                                    'value' => $company } } )
      if defined dbdef->table('cust_main')->column('ship_last');
  }

  if ( $company_type{'Substring'} || $company_type{'All'} ) {

    push @cust_main, qsearch( 'cust_main',
                              { 'company' => { 'op'    => 'ILIKE',
                                               'value' => "%$company%" } } );

    push @cust_main, qsearch( 'cust_main',
                              { 'ship_company' => { 'op'    => 'ILIKE',
                                                    'value' => "%$company%" } })
      if defined dbdef->table('cust_main')->column('ship_last');

  }

  if ( $company_type{'Fuzzy'} || $company_type{'All'} ) {
    push @cust_main, FS::cust_main::Search->fuzzy_search( { 'company' => $company } );
  }

  if ($company_type{'Sound-alike'}) {
  }

  \@cust_main;
}

sub address2search {
  my @cust_main;

  $cgi->param('address2_text') =~
    /^([\w \!\@\#\$\%\&\(\)\-\+\;\:\'\"\,\.\?\/\=]*)$/
      or errorpage(emt("Illegal address2"));
  my $address2 = $1;

  push @cust_main, qsearch( 'cust_main',
                            { 'address2' => { 'op'    => 'ILIKE',
                                              'value' => $address2 } } );
  push @cust_main, qsearch( 'cust_main',
                            { 'ship_address2' => { 'op'    => 'ILIKE',
                                                   'value' => $address2 } } );

  \@cust_main;
}

sub phonesearch {
  my @cust_main;

  my $phone = $cgi->param('phone_text');

  $phone =~ s/\D//g;
  if ( $phone =~ /^(\d{3})(\d{3})(\d{4})(\d*)$/ ) {
    $phone = "$1-$2-$3";
    $phone .= " x$4" if $4;
  } elsif ( $phone =~ /^(\d{3})(\d{4})$/ ) {
    $phone = "$1-$2";
  } elsif ( $phone =~ /^(\d{3,4})$/ ) {
    $phone = $1;
  } else {
    errorpage(gettext('illegal_phone'). ": $phone");
  }

  my @fields = qw(daytime night fax);
  push @fields, qw(ship_daytime ship_night ship_fax)
    if defined dbdef->table('cust_main')->column('ship_last');

  for my $field ( @fields ) {
    push @cust_main, qsearch ( 'cust_main', 
                               { $field => { 'op'    => 'LIKE',
                                             'value' => "%$phone%" } } );
  }

  \@cust_main;
}
</%init>
