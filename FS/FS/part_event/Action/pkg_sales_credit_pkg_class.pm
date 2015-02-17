package FS::part_event::Action::pkg_sales_credit_pkg_class;

use base qw( FS::part_event::Action::Mixin::pkg_sales_credit
             FS::part_event::Action::Mixin::credit_pkg
             FS::part_event::Action::Mixin::credit_sales_pkg_class
             FS::part_event::Action::pkg_sales_credit
             );

sub description { "Credit the package sales person an amount based on their commission percentage for the package's class"; }

1;
