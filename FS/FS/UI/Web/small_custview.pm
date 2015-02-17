package FS::UI::Web::small_custview;

use strict;
use vars qw(@EXPORT_OK @ISA);
use Exporter;
use HTML::Entities;
use FS::Msgcat;
use FS::Record qw(qsearchs);
use FS::cust_main;

@ISA = qw(Exporter);
@EXPORT_OK = qw( small_custview );

=item small_custview CUSTNUM || CUST_MAIN_OBJECT, COUNTRYDEFAULT, NOBALANCE_FLAG, URL

Sheesh. I did switch to mason, but this is still hanging around.  Figure out
some better way to sling mason components to self-service & RT.

=cut

sub small_custview {

  my $arg = shift;
  my $countrydefault = shift || 'US';
  my $nobalance = shift;
  my $url = shift;

  my $cust_main = ref($arg) ? $arg
                  : qsearchs('cust_main', { 'custnum' => $arg } )
    or die "unknown custnum $arg";

  my $html = '<DIV ID="fs_small_custview" CLASS="small_custview">';
  
  $html = qq!<A HREF="$url?! . $cust_main->custnum . '">'
    if $url;

  $html .= 'Customer #<B>'. $cust_main->display_custnum. '</B></A>'.
    ' - <B><FONT COLOR="#'. $cust_main->statuscolor. '">'.
    $cust_main->status_label. '</FONT></B>';

  my @part_tag = $cust_main->part_tag;
  if ( @part_tag ) {
    $html .= '<TABLE>';
    foreach my $part_tag ( @part_tag ) {
      $html .= '<TR><TD>'.
               '<FONT '. ( length($part_tag->tagcolor)
                           ? 'STYLE="background-color:#'.$part_tag->tagcolor.'"'
                           : ''
                         ).
               '>'.
                 encode_entities($part_tag->tagname.': '. $part_tag->tagdesc).
               '</FONT>'.
               '</TD></TR>';
    }
    $html .= '</TABLE>';
  }

  $html .=
    ntable('#e8e8e8'). '<TR><TD VALIGN="top">'. ntable("#cccccc",2).
    '<TR><TD ALIGN="right" VALIGN="top">Billing<BR>Address</TD><TD BGCOLOR="#ffffff">'.
    encode_entities($cust_main->getfield('last')). ', '.
    encode_entities($cust_main->first). '<BR>';

  $html .= encode_entities($cust_main->company). '<BR>' if $cust_main->company;

  if ( $cust_main->bill_locationnum ) {

    $html .= encode_entities($cust_main->address1). '<BR>';
    $html .= encode_entities($cust_main->address2). '<BR>'
      if $cust_main->address2;
    $html .= encode_entities($cust_main->city). ', '. $cust_main->state. '  '.
             $cust_main->zip. '<BR>';
    $html .= $cust_main->country. '<BR>'
      if $cust_main->country && $cust_main->country ne $countrydefault;

  }

  $html .= '</TD></TR><TR><TD></TD><TD BGCOLOR="#ffffff">';
  if ( $cust_main->daytime && $cust_main->night ) {
    $html .= ( FS::Msgcat::_gettext('daytime') || 'Day' ).
             ' '. $cust_main->daytime.
             '<BR>'. ( FS::Msgcat::_gettext('night') || 'Night' ).
             ' '. $cust_main->night;
  } elsif ( $cust_main->daytime || $cust_main->night ) {
    $html .= $cust_main->daytime || $cust_main->night;
  }
  if ( $cust_main->fax ) {
    $html .= '<BR>Fax '. $cust_main->fax;
  }

  $html .= '</TD></TR></TABLE></TD>';

  if ( $cust_main->ship_locationnum ) {

    my $ship = $cust_main->ship_location;

    $html .= '<TD VALIGN="top">'. ntable("#cccccc",2).
      '<TR><TD ALIGN="right" VALIGN="top">Service<BR>Address</TD><TD BGCOLOR="#ffffff">';
    $html .= join('<BR>', 
      map encode_entities($_), grep $_,
        $cust_main->contact,
        $cust_main->company,
        $ship->address1,
        $ship->address2,
        ($ship->city . ', ' . $ship->state . '  ' . $ship->zip),
        ($ship->country eq $countrydefault ? '' : $ship->country ),
    );

    # ship phone numbers no longer exist...

    $html .= '</TD></TR></TABLE></TD>';

  }

  $html .= '</TR></TABLE>';

  $html .= '<BR>Balance: <B>$'. $cust_main->balance. '</B><BR>'
    unless $nobalance;

  # last payment might be good here too?

  $html .= '</DIV>';

  $html;
}

#bah.  don't want to pull in all of FS::CGI, that's the whole problem in the
#first place
sub ntable {
  my $col = shift;
  my $cellspacing = shift || 0;
  if ( $col ) {
    qq!<TABLE BGCOLOR="$col" BORDER=0 CELLSPACING=$cellspacing>!;
  } else {
    '<TABLE BORDER CELLSPACING=0 CELLPADDING=2 BORDERCOLOR="#999999">';
  }

}

1;

