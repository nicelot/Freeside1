package FS::addr_block;
use base qw(FS::Record);

use strict;
use Carp qw( carp );
use List::Util qw( first );
use NetAddr::IP;
use FS::Conf;
use FS::Record qw( qsearch dbh ); #qsearchs
use FS::IP_Mixin;
use FS::addr_range;

=head1 NAME

FS::addr_block - Object methods for addr_block records

=head1 SYNOPSIS

  use FS::addr_block;

  $record = new FS::addr_block \%hash;
  $record = new FS::addr_block { 'column' => 'value' };

  $error = $record->insert;

  $error = $new_record->replace($old_record);

  $error = $record->delete;

  $error = $record->check;

=head1 DESCRIPTION

An FS::addr_block record describes an address block assigned for broadband 
access.  FS::addr_block inherits from FS::Record.  The following fields are 
currently supported:

=over 4

=item blocknum - primary key, used in FS::svc_broadband to associate 
services to the block.

=item routernum - the router (see FS::router) to which this 
block is assigned.

=item ip_gateway - the gateway address used by customers within this block.  

=item ip_netmask - the netmask of the block, expressed as an integer.

=item manual_flag - prohibit automatic ip assignment from this block when true. 

=item agentnum - optional agent number (see L<FS::agent>)

=back

=head1 METHODS

=over 4

=item new HASHREF

Create a new record.  To add the record to the database, see "insert".

=cut

sub table { 'addr_block'; }

=item insert

Adds this record to the database.  If there is an error, returns the error,
otherwise returns false.

=item delete

Deletes this record from the database.  If there is an error, returns the
error, otherwise returns false.

=cut

sub delete {
  my $self = shift;
  return 'Block must be deallocated and have no services before deletion'
    if $self->router || $self->svc_broadband;

    local $SIG{HUP} = 'IGNORE';
    local $SIG{INT} = 'IGNORE';
    local $SIG{QUIT} = 'IGNORE';
    local $SIG{TERM} = 'IGNORE';
    local $SIG{TSTP} = 'IGNORE';
    local $SIG{PIPE} = 'IGNORE';

    my $oldAutoCommit = $FS::UID::AutoCommit;
    local $FS::UID::AutoCommit = 0;
    my $dbh = dbh;
    
    my $error = $self->SUPER::delete;
    if ( $error ) {
       $dbh->rollback if $oldAutoCommit;
       return $error;
    }
  
    $dbh->commit or die $dbh->errstr if $oldAutoCommit;
    '';
}


=item replace OLD_RECORD

Replaces OLD_RECORD with this one in the database.  If there is an error,
returns the error, otherwise returns false.

At present it's not possible to reallocate a block to a different router 
except by deallocating it first, which requires that none of its addresses 
be assigned.  This is probably as it should be.

sub replace_check {
  my ( $new, $old ) = ( shift, shift );

  unless($new->routernum == $old->routernum) {
    my @svc = $self->svc_broadband;
    if (@svc) {
      return 'Block has assigned addresses: '.
             join ', ', map {$_->ip_addr} @svc;
    }

    return 'Block is already allocated'
      if($new->routernum && $old->routernum);

  }

  '';
}

=item check

Checks all fields to make sure this is a valid record.  If there is an error,
returns the error, otherwise returns false.  Called by the insert and replace
methods.

=cut

sub check {
  my $self = shift;

  my $error =
    $self->ut_number('routernum')
    || $self->ut_ip('ip_gateway')
    || $self->ut_number('ip_netmask')
    || $self->ut_enum('manual_flag', [ '', 'Y' ])
    || $self->ut_agentnum_acl('agentnum', 'Broadband global configuration')
  ;
  return $error if $error;


  # A routernum of 0 indicates an unassigned block and is allowed
  return "Unknown routernum"
    if ($self->routernum and not $self->router);

  my $self_addr = $self->NetAddr;
  return "Cannot parse address: ". $self->ip_gateway . '/' . $self->ip_netmask
    unless $self_addr;

  if (not $self->blocknum) {
    my @block = grep {
      my $block_addr = $_->NetAddr;
      if($block_addr->contains($self_addr) 
      or $self_addr->contains($block_addr)) { $_; };
    } qsearch( 'addr_block', {});
    foreach(@block) {
      return "Block intersects existing block ".$_->ip_gateway."/".$_->ip_netmask;
    }
  }

  $self->SUPER::check;
}


=item router

Returns the FS::router object corresponding to this object.  If the 
block is unassigned, returns undef.

=item svc_broadband

Returns a list of FS::svc_broadband objects associated
with this object.

=item NetAddr

Returns a NetAddr::IP object for this block's address and netmask.

=cut

sub NetAddr {
  my $self = shift;
  new NetAddr::IP ($self->ip_gateway, $self->ip_netmask);
}

=item cidr

Returns a CIDR string for this block's address and netmask, i.e. 10.4.20.0/24

=cut

sub cidr {
  my $self = shift;
  $self->NetAddr->cidr;
}

=item next_free_addr

Returns a NetAddr::IP object corresponding to the first unassigned address 
in the block (other than the network, broadcast, or gateway address).  If 
there are no free addresses, returns nothing.  There are never free addresses
when manual_flag is true.

There is no longer a method to return all free addresses in a block.

=cut

sub next_free_addr {
  my $self = shift;
  my $selfaddr = $self->NetAddr;

  return () if $self->manual_flag;

  my $conf = new FS::Conf;
  my @excludeaddr = $conf->config('exclude_ip_addr');

  my %used = map { $_ => 1 }
  (
    @excludeaddr,
    $selfaddr->addr,
    $selfaddr->network->addr,
    $selfaddr->broadcast->addr,
    FS::IP_Mixin->used_addresses($self)
  );

  # just do a linear search of the block
  my $freeaddr = $selfaddr->network + 1;
  while ( $freeaddr < $selfaddr->broadcast ) {
    # also make sure it's not blocked from assignment by an address range
    if ( !$used{$freeaddr->addr } ) {
      my ($range) = grep { !$_->allow_use }
                  FS::addr_range->any_contains($freeaddr->addr);
      if ( !$range ) {
        # then we've found a free address
        return $freeaddr;
      }
      # otherwise, skip to the end of the range
      $freeaddr = NetAddr::IP->new($range->end, $self->ip_netmask);
    }
    $freeaddr++;
  }
  return;

}

=item allocate -- deprecated

Allocates this address block to a router.  Takes an FS::router object 
as an argument.

At present it's not possible to reallocate a block to a different router 
except by deallocating it first, which requires that none of its addresses 
be assigned.  This is probably as it should be.

=cut

sub allocate {
  my ($self, $router) = @_;
  carp "deallocate deprecated -- use replace";

  return 'Block must be allocated to a router'
    unless(ref $router eq 'FS::router');

  my $new = new FS::addr_block {$self->hash};
  $new->routernum($router->routernum);
  return $new->replace($self);

}

=item deallocate -- deprecated

Deallocates the block (i.e. sets the routernum to 0).  If any addresses in the 
block are assigned to services, it fails.

=cut

sub deallocate {
  carp "deallocate deprecated -- use replace";
  my $self = shift;

  my $new = new FS::addr_block {$self->hash};
  $new->routernum(0);
  return $new->replace($self);
}

=item split_block

Splits this address block into two equal blocks, occupying the same space as
the original block.  The first of the two will also have the same blocknum.
The gateway address of each block will be set to the first usable address, i.e.
(network address)+1.  Since this method is designed for use on unallocated
blocks, this is probably the correct behavior.

(At present, splitting allocated blocks is disallowed.  Anyone who wants to
implement this is reminded that each split costs three addresses, and any
customers who were using these addresses will have to be moved; depending on
how full the block was before being split, they might have to be moved to a
different block.  Anyone who I<still> wants to implement it is asked to tie it
to a configuration switch so that site admins can disallow it.)

=cut

sub split_block {

  # We should consider using Attribute::Handlers/Aspect/Hook::LexWrap/
  # something to atomicize functions, so that we can say 
  #
  # sub split_block : atomic {
  # 
  # instead of repeating all this AutoCommit verbage in every 
  # sub that does more than one database operation.

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $self = shift;
  my $error;

  if ($self->router) {
    return 'Block is already allocated';
  }

  #TODO: Smallest allowed block should be a config option.
  if ($self->NetAddr->masklen() ge 30) {
    return 'Cannot split blocks with a mask length >= 30';
  }

  my (@new, @ip);
  $ip[0] = $self->NetAddr;
  @ip = map {$_->first()} $ip[0]->split($self->ip_netmask + 1);

  foreach (0,1) {
    $new[$_] = new FS::addr_block {$self->hash};
    $new[$_]->ip_gateway($ip[$_]->addr);
    $new[$_]->ip_netmask($ip[$_]->masklen);
  }

  $new[1]->blocknum('');

  $error = $new[0]->replace($self);
  if ($error) {
    $dbh->rollback;
    return $error;
  }

  $error = $new[1]->insert;
  if ($error) {
    $dbh->rollback;
    return $error;
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  return '';
}

=item merge

To be implemented.

=item agent

Returns the agent (see L<FS::agent>) for this address block, if one exists.

=item label

Returns text including the router name, gateway ip, and netmask for this
block.

=cut

sub label {
  my $self = shift;
  my $router = $self->router;
  ($router ? $router->routername : '(unallocated)'). ':'. $self->NetAddr;
}

=item router

Returns the router assigned to this block.

=cut

# necessary, because this can't be foreign keyed

sub router {
  my $self = shift;
  my $routernum = $self->routernum;
  if ( $routernum ) {
    return FS::router->by_key($routernum);
  } else {
    return;
  }
}

=back

=head1 BUGS

Minimum block size should be a config option.  It's hardcoded at /30 right
now because that's the smallest block that makes any sense at all.

=cut

1;

