package FS::pay_batch;
use base qw( FS::Record );

use strict;
use vars qw( $DEBUG %import_info %export_info $conf );
use Scalar::Util qw(blessed);
use IO::Scalar;
use List::Util qw(sum);
use Time::Local;
use Text::CSV_XS;
use Date::Parse qw(str2time);
use Business::CreditCard qw(cardtype);
use FS::Misc qw(send_email); # for error notification
use FS::Record qw( dbh qsearch qsearchs );
use FS::Conf;
use FS::cust_pay;

=head1 NAME

FS::pay_batch - Object methods for pay_batch records

=head1 SYNOPSIS

  use FS::pay_batch;

  $record = new FS::pay_batch \%hash;
  $record = new FS::pay_batch { 'column' => 'value' };

  $error = $record->insert;

  $error = $new_record->replace($old_record);

  $error = $record->delete;

  $error = $record->check;

=head1 DESCRIPTION

An FS::pay_batch object represents an payment batch.  FS::pay_batch inherits
from FS::Record.  The following fields are currently supported:

=over 4

=item batchnum - primary key

=item agentnum - optional agent number for agent batches

=item payby - CARD or CHEK

=item status - O (Open), I (In-transit), or R (Resolved)

=item download - time when the batch was first downloaded

=item upload - time when the batch was first uploaded

=item title - unique batch identifier

For incoming batches, the combination of 'title', 'payby', and 'agentnum'
must be unique.

=back

=head1 METHODS

=over 4

=item new HASHREF

Creates a new batch.  To add the batch to the database, see L<"insert">.

Note that this stores the hash reference, not a distinct copy of the hash it
points to.  You can ask the object for a copy with the I<hash> method.

=cut

# the new method can be inherited from FS::Record, if a table method is defined

sub table { 'pay_batch'; }

=item insert

Adds this record to the database.  If there is an error, returns the error,
otherwise returns false.

=cut

# the insert method can be inherited from FS::Record

=item delete

Delete this record from the database.

=cut

# the delete method can be inherited from FS::Record

=item replace OLD_RECORD

Replaces the OLD_RECORD with this one in the database.  If there is an error,
returns the error, otherwise returns false.

=cut

# the replace method can be inherited from FS::Record

=item check

Checks all fields to make sure this is a valid batch.  If there is
an error, returns the error, otherwise returns false.  Called by the insert
and replace methods.

=cut

# the check method should currently be supplied - FS::Record contains some
# data checking routines

sub check {
  my $self = shift;

  my $error = 
    $self->ut_numbern('batchnum')
    || $self->ut_enum('payby', [ 'CARD', 'CHEK' ])
    || $self->ut_enum('status', [ 'O', 'I', 'R' ])
    || $self->ut_foreign_keyn('agentnum', 'agent', 'agentnum')
    || $self->ut_alphan('title')
  ;
  return $error if $error;

  if ( $self->title ) {
    my @existing = 
      grep { !$self->batchnum or $_->batchnum != $self->batchnum } 
      qsearch('pay_batch', {
          payby     => $self->payby,
          agentnum  => $self->agentnum,
          title     => $self->title,
      });
    return "Batch already exists as batchnum ".$existing[0]->batchnum
      if @existing;
  }

  $self->SUPER::check;
}

=item agent

Returns the L<FS::agent> object for this batch.

=item cust_pay_batch

Returns all L<FS::cust_pay_batch> objects for this batch.

=item rebalance

=cut

sub rebalance {
  my $self = shift;
}

=item set_status 

=cut

sub set_status {
  my $self = shift;
  $self->status(shift);
  $self->download(time)
    if $self->status eq 'I' && ! $self->download;
  $self->upload(time)
    if $self->status eq 'R' && ! $self->upload;
  $self->replace();
}

# further false laziness

%import_info = %export_info = ();
foreach my $INC (@INC) {
  warn "globbing $INC/FS/pay_batch/*.pm\n" if $DEBUG;
  foreach my $file ( glob("$INC/FS/pay_batch/*.pm")) {
    warn "attempting to load batch format from $file\n" if $DEBUG;
    $file =~ /\/(\w+)\.pm$/;
    next if !$1;
    my $mod = $1;
    my ($import, $export, $name) = 
      eval "use FS::pay_batch::$mod; 
           ( \\%FS::pay_batch::$mod\::import_info,
             \\%FS::pay_batch::$mod\::export_info,
             \$FS::pay_batch::$mod\::name)";
    $name ||= $mod; # in case it's not defined
    if ($@) {
      # in FS::cdr this is a die, not a warn.  That's probably a bug.
      warn "error using FS::pay_batch::$mod (skipping): $@\n";
      next;
    }
    if(!keys(%$import)) {
      warn "no \%import_info found in FS::pay_batch::$mod (skipping)\n";
    }
    else {
      $import_info{$name} = $import;
    }
    if(!keys(%$export)) {
      warn "no \%export_info found in FS::pay_batch::$mod (skipping)\n";
    }
    else {
      $export_info{$name} = $export;
    }
  }
}

=item import_results OPTION => VALUE, ...

Import batch results.

Options are:

I<filehandle> - open filehandle of results file.

I<format> - an L<FS::pay_batch> module

I<gateway> - an L<FS::payment_gateway> object for a batch gateway.  This 
takes precedence over I<format>.

=cut

sub import_results {
  my $self = shift;

  my $param = ref($_[0]) ? shift : { @_ };
  my $fh = $param->{'filehandle'};
  my $job = $param->{'job'};
  $job->update_statustext(0) if $job;

  my $format = $param->{'format'};
  my $info = $import_info{$format}
    or die "unknown format $format";

  my $conf = new FS::Conf;

  my $filetype            = $info->{'filetype'};      # CSV, fixed, variable
  my @fields              = @{ $info->{'fields'}};
  my $formatre            = $info->{'formatre'};      # for fixed
  my $parse               = $info->{'parse'};         # for variable
  my @all_values;
  my $begin_condition     = $info->{'begin_condition'};
  my $end_condition       = $info->{'end_condition'};
  my $end_hook            = $info->{'end_hook'};
  my $skip_condition      = $info->{'skip_condition'};
  my $hook                = $info->{'hook'};
  my $approved_condition  = $info->{'approved'};
  my $declined_condition  = $info->{'declined'};
  my $close_condition     = $info->{'close_condition'};

  my $csv = new Text::CSV_XS;

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $reself = $self->select_for_update;

  if ( $reself->status ne 'I' 
      and !$conf->exists('batch-manual_approval') ) {
    $dbh->rollback if $oldAutoCommit;
    return "batchnum ". $self->batchnum. "no longer in transit";
  }

  my $total = 0;
  my $line;

  if ($filetype eq 'XML') {
    eval "use XML::Simple";
    die $@ if $@;
    my @xmlkeys = @{ $info->{'xmlkeys'} };  # for XML
    my $xmlrow  = $info->{'xmlrow'};        # also for XML

    # Do everything differently.
    my $data = XML::Simple::XMLin($fh, KeepRoot => 1);
    my $rows = $data;
    # $xmlrow = [ RootKey, FirstLevelKey, SecondLevelKey... ]
    $rows = $rows->{$_} foreach( @$xmlrow );
    if(!defined($rows)) {
      $dbh->rollback if $oldAutoCommit;
      return "can't find rows in XML file";
    }
    $rows = [ $rows ] if ref($rows) ne 'ARRAY';
    foreach my $row (@$rows) {
      push @all_values, [ @{$row}{@xmlkeys}, $row ];
    }
  }
  else {
    while ( defined($line=<$fh>) ) {

      next if $line =~ /^\s*$/; #skip blank lines

      if ($filetype eq "CSV") {
        $csv->parse($line) or do {
          $dbh->rollback if $oldAutoCommit;
          return "can't parse: ". $csv->error_input();
        };
        push @all_values, [ $csv->fields(), $line ];
      }elsif ($filetype eq 'fixed'){
        my @values = ( $line =~ /$formatre/ );
        unless (@values) {
          $dbh->rollback if $oldAutoCommit;
          return "can't parse: ". $line;
        };
        push @values, $line;
        push @all_values, \@values;
      }
      elsif ($filetype eq 'variable') {
        my @values = ( eval { $parse->($self, $line) } );
        if( $@ ) {
          $dbh->rollback if $oldAutoCommit;
          return $@;
        };
        push @values, $line;
        push @all_values, \@values;
      }
      else {
        $dbh->rollback if $oldAutoCommit;
        return "Unknown file type $filetype";
      }
    }
  }

  my $num = 0;
  foreach (@all_values) {
    if($job) {
      $num++;
      $job->update_statustext(int(100 * $num/scalar(@all_values)));
    }
    my @values = @$_;

    my %hash;
    my $line = pop @values;
    foreach my $field ( @fields ) {
      my $value = shift @values;
      next unless $field;
      $hash{$field} = $value;
    }

    if ( defined($begin_condition) ) {
      if ( &{$begin_condition}(\%hash, $line) ) {
        undef $begin_condition;
      }
      else {
        next;
      }
    }

    if ( defined($end_condition) and &{$end_condition}(\%hash, $line) ) {
      my $error;
      $error = &{$end_hook}(\%hash, $total, $line) if defined($end_hook);
      if ( $error ) {
        $dbh->rollback if $oldAutoCommit;
        return $error;
      }
      last;
    }

    if ( defined($skip_condition) and &{$skip_condition}(\%hash, $line) ) {
      next;
    }

    my $cust_pay_batch =
      qsearchs('cust_pay_batch', { 'paybatchnum' => $hash{'paybatchnum'}+0 } );
    unless ( $cust_pay_batch ) {
      return "unknown paybatchnum $hash{'paybatchnum'}\n";
    }
    my $custnum = $cust_pay_batch->custnum,
    my $payby = $cust_pay_batch->payby,

    &{$hook}(\%hash, $cust_pay_batch->hashref);

    my $new_cust_pay_batch = new FS::cust_pay_batch { $cust_pay_batch->hash };

    my $error = '';
    if ( &{$approved_condition}(\%hash) ) {

      foreach ('paid', '_date', 'payinfo') {
        $new_cust_pay_batch->$_($hash{$_}) if $hash{$_};
      }
      $error = $new_cust_pay_batch->approve(%hash);
      $total += $hash{'paid'};

    } elsif ( &{$declined_condition}(\%hash) ) {

      $error = $new_cust_pay_batch->decline($hash{'error_message'});;

    }

    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }

    # purge CVV when the batch is processed
    if ( $payby =~ /^(CARD|DCRD)$/ ) {
      my $payinfo = $hash{'payinfo'} || $cust_pay_batch->payinfo;
      if ( ! grep { $_ eq cardtype($payinfo) }
          $conf->config('cvv-save') ) {
        $new_cust_pay_batch->cust_main->remove_cvv;
      }

    }

  } # foreach (@all_values)

  my $close = 1;
  if ( defined($close_condition) ) {
    # Allow the module to decide whether to close the batch.
    # $close_condition can also die() to abort the whole import.
    $close = eval { $close_condition->($self) };
    if ( $@ ) {
      $dbh->rollback;
      die $@;
    }
  }
  if ( $close ) {
    my $error = $self->set_status('R');
    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  '';

}

use Data::Dumper;
sub process_import_results {
  my $job = shift;
  my $param = shift;
  $param->{'job'} = $job;
  warn Dumper($param) if $DEBUG;
  my $gatewaynum = delete $param->{'gatewaynum'};
  if ( $gatewaynum ) {
    $param->{'gateway'} = FS::payment_gateway->by_key($gatewaynum)
      or die "gatewaynum '$gatewaynum' not found\n";
    delete $param->{'format'}; # to avoid confusion
  }

  my $file = $param->{'uploaded_files'} or die "no files provided\n";
  $file =~ s/^(\w+):([\.\w]+)$/$2/;
  my $dir = '%%%FREESIDE_CACHE%%%/cache.' . $FS::UID::datasrc;
  open( $param->{'filehandle'}, 
        '<',
        "$dir/$file" )
      or die "unable to open '$file'.\n";
  
  my $error;
  if ( $param->{gateway} ) {
    $error = FS::pay_batch->import_from_gateway(%$param);
  } else {
    my $batchnum = delete $param->{'batchnum'} or die "no batchnum specified\n";
    my $batch = FS::pay_batch->by_key($batchnum) or die "batchnum '$batchnum' not found\n";
    $error = $batch->import_results($param);
  }
  unlink $file;
  die $error if $error;
}

=item import_from_gateway [ OPTIONS ]

Import results from a L<FS::payment_gateway>, using Business::BatchPayment,
and apply them.  GATEWAY must use the Business::BatchPayment namespace.

This is a class method, since results can be applied to any batch.  
The 'batch-reconsider' option determines whether an already-approved 
or declined payment can have its status changed by a later import.

OPTIONS may include:

- gateway: the L<FS::payment_gateway>, required
- filehandle: a file name or handle to use as a data source.
- job: an L<FS::queue> object to update with progress messages.

=cut

sub import_from_gateway {
  my $class = shift;
  my %opt = @_;
  my $gateway = $opt{'gateway'};
  my $conf = FS::Conf->new;

  # unavoidable duplication with import_batch, for now
  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $job = delete($opt{'job'});
  $job->update_statustext(0) if $job;

  my $total = 0;
  return "import_from_gateway requires a payment_gateway"
    unless eval { $gateway->isa('FS::payment_gateway') };

  my %proc_opt = (
    'input' => $opt{'filehandle'}, # will do nothing if it's empty
    # any other constructor options go here
  );

  my @item_errors;
  my $mail_on_error = $conf->config('batch-errors_to');
  if ( $mail_on_error ) {
    # construct error trap
    $proc_opt{'on_parse_error'} = sub {
      my ($self, $line, $error) = @_;
      push @item_errors, "  '$line'\n$error";
    };
  }

  my $processor = $gateway->batch_processor(%proc_opt);

  my @batches = $processor->receive;

  my $num = 0;

  my $total_items = sum( map{$_->count} @batches);

  # whether to allow items to change status
  my $reconsider = $conf->exists('batch-reconsider');

  # mutex all affected batches
  my %pay_batch_for_update;

  my %bop2payby = (CC => 'CARD', ECHECK => 'CHEK');

  BATCH: foreach my $batch (@batches) {

    my %incoming_batch = (
      'CARD' => {},
      'CHEK' => {},
    );

    ITEM: foreach my $item ($batch->elements) {

      my $cust_pay_batch; # the new batch entry (with status)
      my $pay_batch; # the freeside batch it belongs to
      my $payby; # CARD or CHEK
      my $error;

      my $paybatch = $gateway->gatewaynum .  '-' .  $gateway->gateway_module .
        ':' . $item->authorization .  ':' . $item->order_number;

      if ( $batch->incoming ) {
        # This is a one-way batch.
        # Locate the customer, find an open batch correct for them,
        # create a payment.  Don't bother creating a cust_pay_batch
        # entry.
        my $cust_main;
        if ( defined($item->customer_id) 
             and $item->customer_id =~ /^\d+$/ 
             and $item->customer_id > 0 ) {

          $cust_main = FS::cust_main->by_key($item->customer_id)
                       || qsearchs('cust_main', 
                         { 'agent_custid' => $item->customer_id }
                       );
          if ( !$cust_main ) {
            push @item_errors, "Unknown customer_id ".$item->customer_id;
            next ITEM;
          }
        }
        else {
          push @item_errors, "Illegal customer_id '".$item->customer_id."'";
          next ITEM;
        }
        # it may also make sense to allow selecting the customer by 
        # invoice_number, but no modules currently work that way

        $payby = $bop2payby{ $item->payment_type };
        my $agentnum = '';
        $agentnum = $cust_main->agentnum if $conf->exists('batch-spoolagent');

        # create a batch if necessary
        $pay_batch = $incoming_batch{$payby}->{$agentnum} ||= 
          FS::pay_batch->new({
              status    => 'R', # pre-resolve it
              payby     => $payby,
              agentnum  => $agentnum,
              upload    => time,
              title     => $batch->batch_id,
          });
        if ( !$pay_batch->batchnum ) {
          $error = $pay_batch->insert;
          die $error if $error; # can't do anything if this fails
        }

        if ( !$item->approved ) {
          $error ||= "payment rejected - ".$item->error_message;
        }
        if ( !defined($item->amount) or $item->amount <= 0 ) {
          $error ||= "no amount in item $num";
        }

        my $payinfo;
        if ( $item->check_number ) {
          $payby = 'BILL'; # right?
          $payinfo = $item->check_number;
        } elsif ( $item->assigned_token ) {
          $payinfo = $item->assigned_token;
        }
        # create the payment
        my $cust_pay = FS::cust_pay->new(
          {
            custnum     => $cust_main->custnum,
            _date       => $item->payment_date->epoch,
            paid        => sprintf('%.2f',$item->amount),
            payby       => $payby,
            invnum      => $item->invoice_number,
            batchnum    => $pay_batch->batchnum,
            payinfo     => $payinfo,
            gatewaynum  => $gateway->gatewaynum,
            processor   => $gateway->gateway_module,
            auth        => $item->authorization,
            order_number => $item->order_number,
          }
        );
        $error ||= $cust_pay->insert;
        eval { $cust_main->apply_payments };
        $error ||= $@;

        if ( $error ) {
          push @item_errors, 'Payment for customer '.$item->customer_id."\n$error";
        }

      } else {
        # This is a request/reply batch.
        # Locate the request (the 'tid' attribute is the paybatchnum).
        my $paybatchnum = $item->tid;
        $cust_pay_batch = FS::cust_pay_batch->by_key($paybatchnum);
        if (!$cust_pay_batch) {
          push @item_errors, "paybatchnum $paybatchnum not found";
          next ITEM;
        }
        $payby = $cust_pay_batch->payby;

        my $batchnum = $cust_pay_batch->batchnum;
        if ( $batch->batch_id and $batch->batch_id != $batchnum ) {
          warn "batch ID ".$batch->batch_id.
                " does not match batchnum ".$cust_pay_batch->batchnum."\n";
        }

        # lock the batch and check its status
        $pay_batch = FS::pay_batch->by_key($batchnum);
        $pay_batch_for_update{$batchnum} ||= $pay_batch->select_for_update;
        if ( $pay_batch->status ne 'I' and !$reconsider ) {
          $error = "batch $batchnum no longer in transit";
        }

        if ( $cust_pay_batch->status ) {
          my $new_status = $item->approved ? 'approved' : 'declined';
          if ( lc( $cust_pay_batch->status ) eq $new_status ) {
            # already imported with this status, so don't touch
            next ITEM;
          }
          elsif ( !$reconsider ) {
            # then we're not allowed to change its status, so bail out
            $error = "paybatchnum ".$item->tid.
            " already resolved with status '". $cust_pay_batch->status . "'";
          }
        }

        if ( $error ) {        
          push @item_errors, "Payment for customer ".$cust_pay_batch->custnum."\n$error";
          next ITEM;
        }

        my $new_payinfo;
        # update payinfo, if needed
        if ( $item->assigned_token ) {
          $new_payinfo = $item->assigned_token;
        } elsif ( $payby eq 'CARD' ) {
          $new_payinfo = $item->card_number if $item->card_number;
        } else { #$payby eq 'CHEK'
          $new_payinfo = $item->account_number . '@' . $item->routing_code
            if $item->account_number;
        }
        $cust_pay_batch->set('payinfo', $new_payinfo) if $new_payinfo;

        # set "paid" pseudo-field (transfers to cust_pay) to the actual amount
        # paid, if the batch says it's different from the amount requested
        if ( defined $item->amount ) {
          $cust_pay_batch->set('paid', $item->amount);
        } else {
          $cust_pay_batch->set('paid', $cust_pay_batch->amount);
        }

        # set payment date to when it was processed
        $cust_pay_batch->_date($item->payment_date->epoch)
          if $item->payment_date;

        # approval status
        if ( $item->approved ) {
          # follow Billing_Realtime format for paybatch
          $error = $cust_pay_batch->approve(
            'gatewaynum'    => $gateway->gatewaynum,
            'processor'     => $gateway->gateway_module,
            'auth'          => $item->authorization,
            'order_number'  => $item->order_number,
          );
          $total += $cust_pay_batch->paid;
        }
        else {
          $error = $cust_pay_batch->decline($item->error_message,
                                            $item->failure_status);
        }

        if ( $error ) {        
          push @item_errors, "Payment for customer ".$cust_pay_batch->custnum."\n$error";
          next ITEM;
        }
      } # $batch->incoming

      $num++;
      $job->update_statustext(int(100 * $num/( $total_items ) ),
        'Importing batch items')
      if $job;

    } #foreach $item

  } #foreach $batch (input batch, not pay_batch)

  # Format an error message
  if ( @item_errors ) {
    my $error_text = join("\n\n", 
      "Errors during batch import: ".scalar(@item_errors),
      @item_errors
    );
    if ( $mail_on_error ) {
      my $subject = "Batch import errors"; #?
      my $body = "Import from gateway ".$gateway->label."\n".$error_text;
      send_email(
        to      => $mail_on_error,
        from    => $conf->config('invoice_from'),
        subject => $subject,
        body    => $body,
      );
    } else {
      # Bail out.
      $dbh->rollback if $oldAutoCommit;
      die $error_text;
    }
  }

  # Auto-resolve (with brute-force error handling)
  foreach my $pay_batch (values %pay_batch_for_update) {
    my $error = $pay_batch->try_to_resolve;

    if ( $error ) {
      $dbh->rollback if $oldAutoCommit;
      return $error;
    }
  }

  $dbh->commit if $oldAutoCommit;
  return;
}

=item try_to_resolve

Resolve this batch if possible.  A batch can be resolved if all of its
entries have status.  If the system options 'batch-auto_resolve_days'
and 'batch-auto_resolve_status' are set, and the batch's download date is
at least (batch-auto_resolve_days) before the current time, then it can
be auto-resolved; entries with no status will be approved or declined 
according to the batch-auto_resolve_status setting.

=cut

sub try_to_resolve {
  my $self = shift;
  my $conf = FS::Conf->new;;

  return if $self->status ne 'I';

  my @unresolved = qsearch('cust_pay_batch',
    {
      batchnum => $self->batchnum,
      status   => ''
    }
  );

  if ( @unresolved and $conf->exists('batch-auto_resolve_days') ) {
    my $days = $conf->config('batch-auto_resolve_days'); # can be zero
    # either 'approve' or 'decline'
    my $action = $conf->config('batch-auto_resolve_status') || '';
    return unless 
      length($days) and 
      length($action) and
      time > ($self->download + 86400 * $days)
      ;

    my $error;
    foreach my $cpb (@unresolved) {
      if ( $action eq 'approve' ) {
        # approve it for the full amount
        $cpb->set('paid', $cpb->amount) unless ($cpb->paid || 0) > 0;
        $error = $cpb->approve($self->batchnum);
      }
      elsif ( $action eq 'decline' ) {
        $error = $cpb->decline('No response from processor');
      }
      return $error if $error;
    }
  } elsif ( @unresolved ) {
    # auto resolve is not enabled, and we're not ready to resolve
    return;
  }

  $self->set_status('R');
}

=item prepare_for_export

Prepare the batch to be exported.  This will:
- Set the status to "in transit".
- If batch-increment_expiration is set and this is a credit card batch,
  increment expiration dates that are in the past.
- If this is the first download for this batch, adjust payment amounts to 
  not be greater than the customer's current balance.  If the customer's 
  balance is zero, the entry will be removed.

Use this within a transaction.

=cut

sub prepare_for_export {
  my $self = shift;
  my $conf = FS::Conf->new;
  my $curuser = $FS::CurrentUser::CurrentUser;

  my $first_download;
  my $status = $self->status;
  if ($status eq 'O') {
    $first_download = 1;
    my $error = $self->set_status('I');
    return "error updating pay_batch status: $error\n" if $error;
  } elsif ($status eq 'I' && $curuser->access_right('Reprocess batches')) {
    $first_download = 0;
  } elsif ($status eq 'R' && 
           $curuser->access_right('Redownload resolved batches')) {
    $first_download = 0;
  } else {
    die "No pending batch.\n";
  }

  my @cust_pay_batch = sort { $a->paybatchnum <=> $b->paybatchnum } 
                       $self->cust_pay_batch;
  
  # handle batch-increment_expiration option
  if ( $self->payby eq 'CARD' ) {
    my ($cmon, $cyear) = (localtime(time))[4,5];
    foreach (@cust_pay_batch) {
      my $etime = str2time($_->exp) or next;
      my ($day, $mon, $year) = (localtime($etime))[3,4,5];
      if( $conf->exists('batch-increment_expiration') ) {
        $year++ while( $year < $cyear or ($year == $cyear and $mon <= $cmon) );
        $_->exp( sprintf('%4u-%02u-%02u', $year + 1900, $mon+1, $day) );
      }
      my $error = $_->replace;
      return $error if $error;
    }
  }

  if ($first_download) { #remove or reduce entries if customer's balance changed

    foreach my $cust_pay_batch (@cust_pay_batch) {

      my $balance = $cust_pay_batch->cust_main->balance;
      if ($balance <= 0) { # then don't charge this customer
        my $error = $cust_pay_batch->delete;
        return $error if $error;
      } elsif ($balance < $cust_pay_batch->amount) {
        # reduce the charge to the remaining balance
        $cust_pay_batch->amount($balance);
        my $error = $cust_pay_batch->replace;
        return $error if $error;
      }
      # else $balance >= $cust_pay_batch->amount
    }
  } #if $first_download

  '';
}

=item export_batch [ format => FORMAT | gateway => GATEWAY ]

Export batch for processing.  FORMAT is the name of an L<FS::pay_batch> 
module, in which case the configuration options are in 'batchconfig-FORMAT'.

Alternatively, GATEWAY can be an L<FS::payment_gateway> object set to a
L<Business::BatchPayment> module.

=cut

sub export_batch {
  my $self = shift;
  my %opt = @_;

  my $conf = new FS::Conf;
  my $batch;

  my $gateway = $opt{'gateway'};
  if ( $gateway ) {
    # welcome to the future
    my $fh = IO::Scalar->new(\$batch);
    $self->export_to_gateway($gateway, 'file' => $fh);
    return $batch;
  }

  my $format = $opt{'format'} || $conf->config('batch-default_format')
    or die "No batch format configured\n";

  my $info = $export_info{$format} or die "Format not found: '$format'\n";

  &{$info->{'init'}}($conf, $self->agentnum) if exists($info->{'init'});

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;  

  my $error = $self->prepare_for_export;

  die $error if $error;
  my $batchtotal = 0;
  my $batchcount = 0;

  my @cust_pay_batch = $self->cust_pay_batch;

  my $delim = exists($info->{'delimiter'}) ? $info->{'delimiter'} : "\n";

  my $h = $info->{'header'};
  if (ref($h) eq 'CODE') {
    $batch .= &$h($self, \@cust_pay_batch). $delim;
  } else {
    $batch .= $h. $delim;
  }

  foreach my $cust_pay_batch (@cust_pay_batch) {
    $batchcount++;
    $batchtotal += $cust_pay_batch->amount;
    $batch .=
    &{$info->{'row'}}($cust_pay_batch, $self, $batchcount, $batchtotal).
    $delim;
  }

  my $f = $info->{'footer'};
  if (ref($f) eq 'CODE') {
    $batch .= &$f($self, $batchcount, $batchtotal). $delim;
  } else {
    $batch .= $f. $delim;
  }

  if ($info->{'autopost'}) {
    my $error = &{$info->{'autopost'}}($self, $batch);
    if($error) {
      $dbh->rollback or die $dbh->errstr if $oldAutoCommit;
      die $error;
    }
  }

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  return $batch;
}

=item export_to_gateway GATEWAY OPTIONS

Given L<FS::payment_gateway> GATEWAY, export the items in this batch to 
that gateway via Business::BatchPayment. OPTIONS may include:

- file: override the default transport and write to this file (name or handle)

=cut

sub export_to_gateway {

  my ($self, $gateway, %opt) = @_;
  
  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;  

  my $error = $self->prepare_for_export;
  die $error if $error;

  my %proc_opt = (
    'output' => $opt{'file'}, # will do nothing if it's empty
    # any other constructor options go here
  );
  my $processor = $gateway->batch_processor(%proc_opt);

  my @items = map { $_->request_item } $self->cust_pay_batch;
  my $batch = Business::BatchPayment->create(Batch =>
    batch_id  => $self->batchnum,
    items     => \@items
  );
  $processor->submit($batch);

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  '';
}

sub manual_approve {
  my $self = shift;
  my $date = time;
  my %opt = @_;
  my $usernum = $opt{'usernum'} || die "manual approval requires a usernum";
  my $conf = FS::Conf->new;
  return 'manual batch approval disabled' 
    if ( ! $conf->exists('batch-manual_approval') );
  return 'batch already resolved' if $self->status eq 'R';
  return 'batch not yet submitted' if $self->status eq 'O';

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $payments = 0;
  foreach my $cust_pay_batch ( 
    qsearch('cust_pay_batch', { batchnum => $self->batchnum,
        status   => '' })
  ) {
    my $new_cust_pay_batch = new FS::cust_pay_batch { 
      $cust_pay_batch->hash,
      'paid'    => $cust_pay_batch->amount,
      '_date'   => $date,
      'usernum' => $usernum,
    };
    my $error = $new_cust_pay_batch->approve();
    # there are no approval options here (authorization, order_number, etc.)
    # because the transaction wasn't really approved
    if ( $error ) {
      $dbh->rollback;
      return 'paybatchnum '.$cust_pay_batch->paybatchnum.": $error";
    }
    $payments++;
  }
  $self->set_status('R');
  $dbh->commit;
  return;
}

sub _upgrade_data {
  # Set up configuration for gateways that have a Business::BatchPayment
  # module.
  
  eval "use Class::MOP;";
  if ( $@ ) {
    warn "Moose/Class::MOP not available.\n$@\nSkipping pay_batch upgrade.\n";
    return;
  }
  my $conf = FS::Conf->new;
  for my $format (keys %export_info) {
    my $mod = "FS::pay_batch::$format";
    if ( $mod->can('_upgrade_gateway') 
        and $conf->exists("batchconfig-$format") ) {

      local $@;
      my ($module, %gw_options) = $mod->_upgrade_gateway;
      my $gateway = FS::payment_gateway->new({
          gateway_namespace => 'Business::BatchPayment',
          gateway_module    => $module,
      });
      my $error = $gateway->insert(%gw_options);
      if ( $error ) {
        warn "Failed to migrate '$format' to a Business::BatchPayment::$module gateway:\n$error\n";
        next;
      }

      # test whether it loads
      my $processor = eval { $gateway->batch_processor };
      if ( !$processor ) {
        warn "Couldn't load Business::BatchPayment module for '$format'.\n";
        # if not, remove it so it doesn't hang around and break things
        $gateway->delete;
      }
      else {
        # remove the batchconfig-*
        warn "Created Business::BatchPayment gateway '".$gateway->label.
             "' for '$format' batch processing.\n";
        $conf->delete("batchconfig-$format");

        # and if appropriate, make it the system default
        for my $payby (qw(CARD CHEK)) {
          if ( ($conf->config("batch-fixed_format-$payby") || '') eq $format ) {
            warn "Setting as default for $payby.\n";
            $conf->set("batch-gateway-$payby", $gateway->gatewaynum);
            $conf->delete("batch-fixed_format-$payby");
          }
        }
      } # if $processor
    } #if can('_upgrade_gateway') and batchconfig-$format
  } #for $format

  '';
}

=back

=head1 BUGS

status is somewhat redundant now that download and upload exist

=head1 SEE ALSO

L<FS::Record>, schema.html from the base documentation.

=cut

1;

