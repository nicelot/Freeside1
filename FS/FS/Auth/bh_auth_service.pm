package FS::Auth::bh_auth_service;

use strict;
use base qw( FS::Auth::external );
use lib '/var/skynet/lib';
use config;
use API::Client;

sub authenticate {
  my($self, $username, $check_password, $info ) = @_;

  my $c=API::Client->new({service=>"emp_auth"});
  use Debug;
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
    my @name = split(/\s/, $ret->{data}->{name} );

    ##TODO: check for a 'freeside' or billing interface permission:
    #
    $info->{'first'}  = shift @name;
    $info->{'last'}  = "@name";
    #$info->{'template_user'} = '';  #TODO: some lookup in the roster data to see what permissions they need
    return 1;
  } else {
    ## bad login
    return 0;
  }
  return $ret;
}

sub verify_user {
  my ($self, $curuser) = @_;
  return time() % 5 if $curuser->username eq 'testsubject';
  return 1;
}

1;
