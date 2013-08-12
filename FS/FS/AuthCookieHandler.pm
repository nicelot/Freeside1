package FS::AuthCookieHandler;
use base qw( Apache2::AuthCookie );

use strict;
use FS::UID qw( adminsuidsetup preuser_setup );
use FS::CurrentUser;
use FS::Auth;

sub authen_cred {
  my( $self, $r, $username, $password ) = @_;

  preuser_setup();

  my $info = {};

  my $sessionkey;
  unless ( $sessionkey = FS::Auth->authenticate($username, $password, $info) ) {
    warn "failed auth $username from ". $r->connection->remote_ip. "\n";
    return undef;
  }

  warn "authenticated $username from ". $r->connection->remote_ip. "\n";

  FS::CurrentUser->load_user( $username,
                              'autocreate' => FS::Auth->auth_class->autocreate,
                              %$info,
                            );

  FS::CurrentUser->new_session($sessionkey);
}

sub authen_ses_key {
  my( $self, $r, $sessionkey ) = @_;

  preuser_setup();

  my $curuser = FS::CurrentUser->load_user_session( $sessionkey );

  unless ( $curuser ) {
    warn "bad session $sessionkey from ". $r->connection->remote_ip. "\n";
    return undef;
  }

  my $new_sessionkey;
  unless ( $new_sessionkey = FS::Auth->verify_user( $curuser, $sessionkey ) ) {
    warn "bad verify_user $sessionkey from ". $r->connection->remote_ip. "\n";
    return undef;
  }
  if ($new_sessionkey ne $sessionkey && $new_sessionkey ne 1) {
    FS::CurrentUser->new_session($new_sessionkey);
    Apache2::AuthCookie->send_cookie($r, $new_sessionkey);
  }

  $curuser->username;
}

1;
