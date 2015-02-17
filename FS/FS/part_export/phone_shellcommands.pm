package FS::part_export::phone_shellcommands;

use strict;
use vars qw(@ISA %info);
use Tie::IxHash;
use String::ShellQuote;
use FS::part_export;

@ISA = qw(FS::part_export);

#TODO
#- modify command (get something from freepbx for changing PINs)
#- suspension/unsuspension

tie my %options, 'Tie::IxHash',
  'user'       => { label=>'Remote username', default=>'root', },
  'useradd'    => { label=>'Insert command', }, 
  'userdel'    => { label=>'Delete command', }, 
  'usermod'    => { label=>'Modify command', }, 
  'suspend'    => { label=>'Suspension command', }, 
  'unsuspend'  => { label=>'Unsuspension command', }, 
  'mac_insert' => { label=>'Device MAC address insert command', },
  'mac_delete' => { label=>'Device MAC address delete command', },
;

%info = (
  'svc'     => [qw( svc_phone part_device )],
  'desc'    => 'Run remote commands via SSH, for phone numbers',
  'options' => \%options,
  'notes'   => <<'END'
Run remote commands via SSH, for phone numbers.  You will need to
<a href="http://www.freeside.biz/mediawiki/index.php/Freeside:1.9:Documentation:Administration:SSH_Keys">setup SSH for unattended operation</a>.
<BR><BR>Use these buttons for some useful presets:
<UL>
  <LI>
    <INPUT TYPE="button" VALUE="FreePBX (build_exten CLI module needed)" onClick='
      this.form.user.value = "root";
      this.form.useradd.value = "build_exten.php --create --exten $phonenum --directdid 1$phonenum --sip-secret $sip_password --name $cust_name --vm-password $pin && /usr/share/asterisk/bin/module_admin reload";
      this.form.userdel.value = "build_exten.php --delete --exten $phonenum && /usr/share/asterisk/bin/module_admin reload";
      this.form.usermod.value = "build_exten.php --modify --exten $new_phonenum --directdid 1$new_phonenum --sip-secret $new_sip_password --name $new_cust_name --vm-password $new_pin && /usr/share/asterisk/bin/module_admin reload";
      this.form.suspend.value = "";
      this.form.unsuspend.value = "";
    '> (Important note: Reduce freeside-queued "max_kids" to 1 when using FreePBX integration)
  </UL>

The following variables are available for interpolation (prefixed with new_ or
old_ for replace operations):
<UL>
  <LI><code>$countrycode</code> - Country code
  <LI><code>$phonenum</code> - Phone number
  <LI><code>$sip_password</code> - SIP secret (quoted for the shell)
  <LI><code>$pin</code> - Personal identification number
  <LI><code>$cust_name</code> - Customer name (quoted for the shell)
  <LI><code>$pkgnum</code> - Internal package number
  <LI><code>$custnum</code> - Internal customer number
  <LI><code>$phone_name</code> - Phone name (quoted for the shell)
  <LI><code>$mac_addr</code> - MAC address (Device MAC address insert and delete commands only)
  <LI><code>$devicename</code> - Device type (Device type insert and delete commands only)
</UL>
END
);

sub rebless { shift; }

sub _export_insert {
  my $self = shift;
  $self->_export_command('useradd', @_);
}

sub _export_delete {
  my $self = shift;
  $self->_export_command('userdel', @_);
}

sub _export_suspend {
  my $self = shift;
  $self->_export_command('suspend', @_);
}

sub _export_unsuspend {
  my $self = shift;
  $self->_export_command('unsuspend', @_);
}

sub export_device_insert {
  my( $self, $svc_phone, $phone_device ) = @_;
  $self->_export_command('mac_insert', $svc_phone,
                           mac_addr   => $phone_device->mac_addr,
                           devicename => $phone_device->part_device->devicename,
                        );
}

sub export_device_delete {
  my( $self, $svc_phone, $phone_device ) = @_;
  $self->_export_command('mac_delete', $svc_phone,
                           mac_addr   => $phone_device->mac_addr,
                           devicename => $phone_device->part_device->devicename,
                        );
}

sub _export_command {
  my ( $self, $action, $svc_phone, %addl_vars) = @_;
  my $command = $self->option($action);
  return '' if $command =~ /^\s*$/;

  #set variable for the command
  no strict 'vars';
  {
    no strict 'refs';
    ${$_} = $svc_phone->getfield($_) foreach $svc_phone->fields;
    ${$_} = $addl_vars{$_} foreach keys %addl_vars;
  }
  my $cust_pkg = $svc_phone->cust_svc->cust_pkg;
  my $pkgnum = $cust_pkg ? $cust_pkg->pkgnum : '';
  my $custnum = $cust_pkg ? $cust_pkg->custnum : '';
  my $cust_name = $cust_pkg ? $cust_pkg->cust_main->name : '';
  $cust_name = shell_quote $cust_name;
  my $sip_password = shell_quote $svc_phone->sip_password;
  my $phone_name = shell_quote $svc_phone->phone_name;
  #done setting variables for the command

  $self->shellcommands_queue( $svc_phone->svcnum,
    user         => $self->option('user')||'root',
    host         => $self->machine,
    command      => eval(qq("$command")),
  );
}

sub _export_replace {
  my($self, $new, $old ) = (shift, shift, shift);
  my $command = $self->option('usermod');
  
  #set variable for the command
  no strict 'vars';
  {
    no strict 'refs';
    ${"old_$_"} = $old->getfield($_) foreach $old->fields;
    ${"new_$_"} = $new->getfield($_) foreach $new->fields;
  }

  my $old_cust_pkg = $old->cust_svc->cust_pkg;
  my $old_pkgnum = $old_cust_pkg ? $old_cust_pkg->pkgnum : '';
  my $old_custnum = $old_cust_pkg ? $old_cust_pkg->custnum : '';
  my $cust_pkg = $new->cust_svc->cust_pkg;
  my $new_pkgnum = $cust_pkg ? $cust_pkg->pkgnum : '';
  my $new_custnum = $new_cust_pkg ? $new_cust_pkg->custnum : '';
  my $new_cust_name = $cust_pkg ? $cust_pkg->cust_main->name : '';
  $new_cust_name = shell_quote $new_cust_name;
  #done setting variables for the command

  $self->shellcommands_queue( $new->svcnum,
    user         => $self->option('user')||'root',
    host         => $self->machine,
    command      => eval(qq("$command")),
  );
}

#a good idea to queue anything that could fail or take any time
sub shellcommands_queue {
  my( $self, $svcnum ) = (shift, shift);
  my $queue = new FS::queue {
    'svcnum' => $svcnum,
    'job'    => "FS::part_export::phone_shellcommands::ssh_cmd",
  };
  $queue->insert( @_ );
}

sub ssh_cmd { #subroutine, not method
  use Net::SSH '0.08';
  &Net::SSH::ssh_cmd( { @_ } );
}

1;
