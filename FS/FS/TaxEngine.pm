package FS::TaxEngine;

use strict;
use vars qw( $DEBUG );
use FS::Conf;
use FS::Record qw(qsearch qsearchs);

$DEBUG = 0;

=head1 NAME

FS::TaxEngine - Base class for tax calculation engines.

=head1 USAGE

1. At the start of creating an invoice, create an FS::TaxEngine object.
2. Each time a sale item is added to the invoice, call C<add_sale> on the 
   TaxEngine.

- If the TaxEngine is "batch" style (Billsoft):
3. Set the "pending" flag on the invoice.
4. Insert the invoice and its line items.
5. After creating all invoices for the day, call 
   FS::TaxEngine::process_tax_batch.  This will create the tax items for
   all of the pending invoices, clear the "pending" flag, and call 
   C<collect> on each of the billed customers.

- If not (the internal tax system, CCH):
3. After adding all sale items, call C<calculate_taxes> on the TaxEngine to
   produce a list of tax line items.
4. Append the tax line items to the invoice.
5. Insert the invoice.

=head1 CLASS METHODS

=over 4

=item new 'cust_main' => CUST_MAIN, 'invoice_time' => TIME, OPTIONS...

Creates an L<FS::TaxEngine> object.  The subclass will be chosen by the 
'enable_taxproducts' configuration setting.

CUST_MAIN and TIME are required.  OPTIONS can include "cancel" => 1 to 
indicate that the package is being billed on cancellation.

=cut

sub new {
  my $class = shift;
  my %opt = @_;
  if ($class eq 'FS::TaxEngine') {
    my $conf = FS::Conf->new;
    my $subclass = $conf->config('enable_taxproducts') || 'internal';
    $class .= "::$subclass";
    local $@;
    eval "use $class";
    die "couldn't load $class: $@\n" if $@;
  }
  my $self = { items => [], taxes => {}, %opt };
  bless $self, $class;
}

=item info

Returns a hashref of metadata about this tax method, including:
- batch: whether this is a batch-style engine (requires different usage)
- override: whether this engine uses tax overrides
- manual_tax_location: whether this engine requires the user to select a "tax
  location" separate from the address/city/state/zip fields
- rate_table: the table that stores the tax rates
  (the 'taxline' method of that class will be used to calculate line-item
   taxes)
- link_table: the table that links L<FS::cust_bill_pkg> records for taxes
  to the C<rate_table> entry that generated them, and to the item they 
  represent tax on.

=back

=head1 METHODS

=over 4

=item add_sale CUST_BILL_PKG

Adds the CUST_BILL_PKG object as a taxable sale on this invoice.

=item calculate_taxes CUST_BILL

Calculates the taxes on the taxable sales and returns a list of 
L<FS::cust_bill_pkg> objects to add to the invoice.  There is a base 
implementation of this, which calls the C<taxline> method to calculate
each individual tax.

=cut

sub calculate_taxes {
  my $self = shift;
  my $conf = FS::Conf->new;

  my $cust_bill = shift;

  my @tax_line_items;
  # keys are tax names (as printed on invoices / itemdesc )
  # values are arrayrefs of taxlines
  my %taxname;

  # keys are taxnums
  # values are (cumulative) amounts
  my %tax_amount;

  # keys are taxnums
  # values are arrayrefs of cust_tax_exempt_pkg objects
  my %tax_exemption;

  # For each distinct tax rate definition, calculate the tax and exemptions.
  foreach my $taxnum ( keys %{ $self->{taxes} } ) {

    my $taxables = $self->{taxes}{$taxnum};
    my $tax_object = shift @$taxables;
    # $tax_object is a cust_main_county or tax_rate 
    # (with billpkgnum, pkgnum, locationnum set)
    # the rest of @{ $taxlisthash->{$tax} } is cust_bill_pkg component objects
    # (setup, recurring, usage classes)

    my $taxline = $self->taxline('tax' => $tax_object, 'sales' => $taxables);
    # taxline methods are now required to return real line items
    # with their link records
    die $taxline unless ref($taxline);

    push @{ $taxname{ $taxline->itemdesc } }, $taxline;

  } #foreach $taxnum

  my $link_table = $self->info->{link_table};
  # For each distinct tax name (the values set as $taxline->itemdesc),
  # create a consolidated tax item with the total amount and all the links
  # of all tax items that share that name.
  foreach my $taxname ( keys %taxname ) {
    my @tax_links;
    my $tax_cust_bill_pkg = FS::cust_bill_pkg->new({
        'invnum'    => $cust_bill->invnum,
        'pkgnum'    => 0,
        'recur'     => 0,
        'sdate'     => '',
        'edate'     => '',
        'itemdesc'  => $taxname,
        $link_table => \@tax_links,
    });

    my $tax_total = 0;
    warn "adding $taxname\n" if $DEBUG > 1;

    foreach my $taxitem ( @{ $taxname{$taxname} } ) {
      # then we need to transfer the amount and the links from the
      # line item to the new one we're creating.
      $tax_total += $taxitem->setup;
      foreach my $link ( @{ $taxitem->get($link_table) } ) {
        $link->set('tax_cust_bill_pkg', $tax_cust_bill_pkg);
        push @tax_links, $link;
      }
    } # foreach $taxitem
    next unless $tax_total;

    # we should really neverround this up...I guess it's okay if taxline 
    # already returns amounts with 2 decimal places
    $tax_total = sprintf('%.2f', $tax_total );
    $tax_cust_bill_pkg->set('setup', $tax_total);

    my $pkg_category = qsearchs( 'pkg_category', { 'categoryname' => $taxname,
                                                   'disabled'     => '',
                                                 },
                               );

    my @display = ();
    if ( $pkg_category and
         $conf->config('invoice_latexsummary') ||
         $conf->config('invoice_htmlsummary')
       )
    {
      my %hash = (  'section' => $pkg_category->categoryname );
      push @display, new FS::cust_bill_pkg_display { type => 'S', %hash };
    }
    $tax_cust_bill_pkg->set('display', \@display);

    push @tax_line_items, $tax_cust_bill_pkg;
  }

  \@tax_line_items;
}

=head1 CLASS METHODS

=item cust_tax_locations LOCATION

Given an L<FS::cust_location> object (or a hash of location fields), 
returns a list of all tax jurisdiction locations that could possibly 
match it.  This is meant for interactive use: the location editing UI
displays the candidate locations to the user so they can choose the 
best match.

=cut

sub cust_tax_locations {
  ();
} # shouldn't even get called unless info->{manual_tax_location} is true

=item add_taxproduct DESCRIPTION

If the module allows manually adding tax products (categories of taxable
items/services), this method will be called to do it. (If not, the UI in
browse/part_pkg_taxproduct/* should prevent adding an unlisted tax product.
That is the default behavior, so by default this method simply fails.)

DESCRIPTION is the contents of the taxproduct_description form input, which
will normally be filled in by browse/part_pkg_taxproduct/*.

Must return the newly inserted part_pkg_taxproduct object on success, or
a string on failure.

=cut

sub add_taxproduct {
  my $class = shift;
  "$class does not allow manually adding taxproducts";
}

=item transfer_batch (batch-style only)

Submits the pending transaction batch for processing, receives the 
results, and appends the calculated taxes to all invoices that were 
included in the batch.  Then clears their pending flags, and queues
a job to run C<FS::cust_main::Billing::collect> on each affected
customer.

=back

=cut

1;
