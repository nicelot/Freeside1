package FS::Auth;

use strict;
use FS::Conf;

=head1 NAME

FS::Auth

=head1 DESCRIPTION

The following methods are currently supported:

=over 4

=item authenticate USERNAME, PASSWORD, OTHER

Used to authenticate the user.

If the USERNAME/PASSWORD are valid returns a sessionkey, otherwise returns false.

=cut

sub authenticate {
  my $class = shift;

  $class->auth_class->authenticate(@_);
}

=item verify_user ACCESS_USER SESSION_KEY 

Verifies that the user is still valid.

This method is used by FS::AuthCookieHandler to verify that the user cookie is still allowed access to freeside.

Since this is called by nearly every page, it should a VERY light weight call.

Ideally your custom auth module will internally cache the result for a short duration.  Say 1 to 5 minutes.  And re-poll your external auth environment to make certain the user has not been fired or otherwise lost their privileges.

If USER/SESSION are valid returns true, otherwise returns false.

=cut

sub verify_user {
  my $class = shift;
  # FS::access_user object
  # sessionkey

  $class->auth_class->verify_user(@_);
}

sub auth_class {
  #my($class) = @_;

  my $conf = new FS::Conf;
  my $module = lc($conf->config('authentication_module')) || 'internal';

  my $auth_class = 'FS::Auth::'.$module;
  eval "use $auth_class;";
  die $@ if $@;

  $auth_class;
}

1;
