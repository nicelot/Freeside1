<% include( 'elements/svc_Common.html',
            'table'   	=> 'svc_dish',
            'html_foot' => $html_foot,
            'fields'    => \@fields,
    )
%>
<%init>

die "access denied"
  unless $FS::CurrentUser::CurrentUser->access_right('Provision customer service'); #something else more specific?

my $conf = new FS::Conf;
my $date_format = $conf->config('date_format') || '%m/%d/%Y';

my $html_foot = sub { };

my @fields = (
  {
    field => 'acctnum',
    type  => 'text',
    label => 'DISH Account #',
  },
  {
    field => 'installdate',
    type  => 'input-date-field',
    label => 'Install date',
  },
  {
    field => 'note',
    type  => 'textarea',
    rows  => 8,
    cols  => 50,
    label => 'Installation notes',
  },

);
    
</%init>
