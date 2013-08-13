package FS::Auth::bh_auth_service;

use strict;
use base qw( FS::Auth::external );
use lib '/var/skynet/lib';
use config;
use API::Client;
use AuthService;
use Debug;

sub authenticate {
  my($self, $username, $check_password, $info ) = @_;

  my $c=API::Client->new({service=>"emp_auth"});
  my $ret = $c->verify_pass(
    {
      user => $username,
      pass=> $check_password,
      emp_info => 1,
    }
  );
  if(!$ret) {
    return 0;
  }

  if( $ret->{data}->{'valid'} == 1 ) {
    my @name = split(/\s/, $ret->{data}->{emp_info}->{name} );
    $info->{'first'}  = shift @name;
    $info->{'last'}  = "@name";

    #TODO: set memcache token, ret, 5 minutes
    return FS::Auth::bh_auth_service->check_permissions($username,$ret,$info);
  }
  ## bad login
  return 0;
}

sub verify_user {
  my ($self, $curuser, $sessionkey) = @_;

  my $fullkey = $curuser->username.$sessionkey; # reassemble the full bluehost key (it was split in bh_auth_service::Authenticate above)
  #TODO: get memcache token, ret

  if ( $fullkey =~ m{ ^(\w+) / ([^/]+) / ([^/]+) / (.*) / ([^/]+) / (sh\.\d+\.\d+)$ }x ) {
    my %req = (
      user        => $1,
      cram_time   => $2,
      expires_min => $3,
      payload     => $4,
      test_pass   => $5,
      secure_hash => $6,
      token       => $fullkey,
      who         => $1,
      emp_info => 1,
    );
    $req{'ip'} = join ".", unpack( "C4", pack( "N", hex($1) ) )
    if $req{'payload'} =~ /\bi:([a-f0-9]{1,8})/; # TODO: we don't care about ip - just yet - spoof it

    my $c=API::Client->new({service=>"emp_auth"});
    my $ret = $c->verify_pass( \%req );

    if ($ret->{data}->{'valid'}) {
      #TODO: set memcache token, ret, 5 minutes
      return FS::Auth::bh_auth_service->check_permissions($req{user},$ret);
    }
  }

  ## bad sessionkey
  return 0;
}

sub check_permissions {
  my ($self, $username, $ret, $info) = @_;

  my $template_user = FS::Auth::bh_auth_service->find_template($ret);
  $info->{'template_user'} = $template_user if defined $template_user;

  my $disabled = undef;
  if (defined $ret->{data}->{emp_info}->{end_date} && $ret->{data}->{emp_info}->{end_date} != '' && $ret->{data}->{emp_info}->{end_date} != '0000-00-00') {
    $disabled = 'Y';
    warn 'User: '.$username.' attempted to login.  Yet records show they are terminated.';
  }

  eval "use FS::Record qw(qsearchs);";
  die $@ if $@;
  eval "use FS::access_user;";
  die $@ if $@;

  my $CurrentUser = qsearchs('access_user', {username=>$username});
  if($CurrentUser) {
    if ( $CurrentUser->disabled ne $disabled ) {
      $CurrentUser->set('disabled', $disabled);
      my $error;
      eval { $error = $CurrentUser->replace; };
      die $error if $error && $error !~ /records identical/; #better way to handle this error?
    }

    eval "use FS::access_usergroup;";
    die $@ if $@;
    my $tmpl_access_user =
       qsearchs('access_user', { 'username' => $template_user } );

    my @allowed_groupnums;
    my @original_usergroups = $CurrentUser->access_usergroup;
    my @original_groupnums;
    foreach my $tmpl_access_usergroup (@original_usergroups) {
      push @original_groupnums, $tmpl_access_usergroup->groupnum;
    }

    if ($tmpl_access_user) {
      my @allowed_usergroups = $tmpl_access_user->access_usergroup;
      foreach my $tmpl_access_usergroup (@allowed_usergroups) {
        push @allowed_groupnums, $tmpl_access_usergroup->groupnum;
        next if $tmpl_access_usergroup->groupnum ~~ @original_groupnums; # they already belond to this group
        warn "Adding new permission to $username -> ".$tmpl_access_usergroup->groupnum;
        my $access_usergroup = new FS::access_usergroup {
          'usernum'  => $CurrentUser->usernum,
          'groupnum' => $tmpl_access_usergroup->groupnum,
        };
        my $error = $access_usergroup->insert;
        if ( $error ) {
          #shouldn't happen, but seems better to proceed than to die
          warn "error inserting access_usergroup: $error";
        };
      }
    } else {
      # no template found, remove all user access
      warn "Template $template_user not found";
    }
    foreach my $tmpl_access_usergroup (@original_usergroups) {
      # removes any old permissions that this user had at one point.
      # If no template is found it removes ALL permissions.
      next if $tmpl_access_usergroup->groupnum ~~ @allowed_groupnums;
      warn "Removing permission from $username -> ".$tmpl_access_usergroup->groupnum;
      my $error = $tmpl_access_usergroup->delete;
      if ( $error ) {
        #shouldn't happen, but seems better to proceed than to die
        warn "error deleting access_usergroup: $error";
      }
    }
  }
  return 0 if defined $disabled && $disabled eq 'Y';

  # freeside only allow 80 character session keys.  Our session is longer than that because
  # it begins with the username, so lets strip the username off and then it will fit.
  my $tmp_key = $ret->{data}->{'token'};
  return substr($tmp_key,length($username),length($tmp_key));
}

sub find_template {
  my ($self, $ret) = @_;
  # TODO: more complex template script
  my $group = $ret->{data}->{emp_info}->{'group_name'};
  return undef if ! defined $group;
  if ($group eq 'Developers' && $ret->{data}->{emp_info}->{permissions}->{'app.wallboard.card_service'}) {
    $group = 'Superuser';
  }
  $group = lc('template_'.$group);
  $group =~ s/[^a-z0-9]/_/g;
  return $group;
}

1;
