package FS::Cron::upload;

use strict;
use vars qw( @ISA @EXPORT_OK $me $DEBUG );
use Exporter;
use Date::Format;
use FS::UID qw(dbh);
use FS::Record qw( qsearch qsearchs );
use FS::Conf;
use FS::queue;
use FS::agent;
use FS::Log;
use FS::Misc qw( send_email ); #for bridgestone
use FS::upload_target;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Request::Common;
use HTTP::Response;
use Net::FTP;
use List::Util qw( sum );

@ISA = qw( Exporter );
@EXPORT_OK = qw ( upload );
$DEBUG = 0;
$me = '[FS::Cron::upload]';

#freeside-daily %opt:
#  -v: enable debugging
#  -l: debugging level
#  -m: Experimental multi-process mode uses the job queue for multi-process and/or multi-machine billing.
#  -r: Multi-process mode dry run option
#  -a: Only process customers with the specified agentnum


sub upload {
  my %opt = @_;
  my $log = FS::Log->new('Cron::upload');
  $log->info('start');

  my $debug = 0;
  $debug = 1 if $opt{'v'};
  $debug = $opt{'l'} if $opt{'l'};

  local $DEBUG = $debug if $debug;

  warn "$me upload called\n" if $DEBUG;

  my @tasks;

  my $date =  time2str('%Y%m%d%H%M%S', $^T); # more?

  my $conf = new FS::Conf;

  my @agents = $opt{'a'} ? FS::agent->by_key($opt{'a'}) : qsearch('agent', {});

  my %task = (
    'date'      => $date,
    'l'         => $opt{'l'},
    'm'         => $opt{'m'},
    'v'         => $opt{'v'},
  );

  my @agentnums = ('', map {$_->agentnum} @agents);

  foreach my $target (qsearch('upload_target', {})) {
    # We don't know here if it's spooled on a per-agent basis or not.
    # (It could even be both, via different events.)  So queue up an 
    # upload for each agent, plus one with null agentnum, and we'll 
    # upload as many files as we find.
    foreach my $a (@agentnums) {
      push @tasks, {
        %task,
        'agentnum'  => $a,
        'targetnum' => $target->targetnum,
        'handling'  => $target->handling,
      };
    }
  }

  # deprecated billco method
  foreach (@agents) {
    my $agentnum = $_->agentnum;

    if ( $conf->config( 'billco-username', $agentnum, 1 ) ) {
      my $username = $conf->config('billco-username', $agentnum, 1);
      my $password = $conf->config('billco-password', $agentnum, 1);
      my $clicode  = $conf->config('billco-clicode',  $agentnum, 1);
      my $url      = $conf->config('billco-url',      $agentnum);
      push @tasks, {
        %task,
        'agentnum' => $agentnum,
        'username' => $username,
        'password' => $password,
        'url'      => $url,
        'clicode'  => $clicode,
        'handling' => 'billco',
      };
    }
  } # foreach @agents

  # if there's nothing to do, don't hold up the rest of the process
  if (!@tasks) {
    $log->info('finish (nothing to upload)');
    return '';
  }

  # wait for any ongoing billing jobs to complete
  if ($opt{m}) {
    my $dbh = dbh;
    my $sql = "SELECT count(*) FROM queue LEFT JOIN cust_main USING(custnum) ".
    "WHERE queue.job='FS::cust_main::queued_bill' AND status != 'failed'";
    if (@agents) {
      $sql .= ' AND cust_main.agentnum IN('.
        join(',', map {$_->agentnum} @agents).
        ')';
    }
    my $sth = $dbh->prepare($sql) or die $dbh->errstr;
    while (1) {
      $sth->execute()
        or die "Unexpected error executing statement $sql: ". $sth->errstr;
      last if $sth->fetchrow_arrayref->[0] == 0;
      warn "Waiting 5min for billing to complete...\n" if $DEBUG;
      sleep 300;
    }
  }

  foreach (@tasks) {

    my $agentnum = $_->{agentnum};

    if ( $opt{'m'} ) {

      if ( $opt{'r'} ) {
        warn "DRY RUN: would add agent $agentnum for queued upload\n";
      } else {
        my $queue = new FS::queue {
          'job'      => 'FS::Cron::upload::spool_upload',
        };
        my $error = $queue->insert( %$_ );
      }

    } else {

      eval { spool_upload(%$_) };
      warn "spool_upload failed: $@\n"
        if $@;

    }

  }
  $log->info('finish');

}

sub spool_upload {
  my %opt = @_;
  my $log = FS::Log->new('spool_upload');

  warn "$me spool_upload called\n" if $DEBUG;
  my $conf = new FS::Conf;
  my $dir = '%%%FREESIDE_EXPORT%%%/export.'. $FS::UID::datasrc. '/cust_bill';

  my $date = $opt{date} or die "no date provided\n";

  local $SIG{HUP} = 'IGNORE';
  local $SIG{INT} = 'IGNORE';
  local $SIG{QUIT} = 'IGNORE';
  local $SIG{TERM} = 'IGNORE';
  local $SIG{TSTP} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';

  my $oldAutoCommit = $FS::UID::AutoCommit;
  local $FS::UID::AutoCommit = 0;
  my $dbh = dbh;

  my $agentnum = $opt{agentnum};
  $log->debug('start', agentnum => $agentnum);

  my $agent;
  if ( $agentnum ) {
    $agent = qsearchs( 'agent', { agentnum => $agentnum } )
      or die "no such agent: $agentnum";
    $agent->select_for_update; #mutex 
  }

  if ( $opt{'handling'} eq 'billco' ) {

    my $file = "agentnum$agentnum";
    my $zipfile  = "$dir/$file-$date.zip";

    unless ( -f "$dir/$file-header.csv" ||
             -f "$dir/$file-detail.csv" )
    {
      warn "$me neither $dir/$file-header.csv nor ".
           "$dir/$file-detail.csv found\n" if $DEBUG > 1;
      $log->debug("finish (neither $file-header.csv nor ".
           "$file-detail.csv found)");
      $dbh->commit or die $dbh->errstr if $oldAutoCommit;
      return;
    }

    my $url      = $opt{url} or die "no url for agent $agentnum\n";
    $url =~ s/^\s+//; $url =~ s/\s+$//;

    my $username = $opt{username} or die "no username for agent $agentnum\n";
    my $password = $opt{password} or die "no password for agent $agentnum\n";

    foreach ( qw ( header detail ) ) {
      rename "$dir/$file-$_.csv",
             "$dir/$file-$date-$_.csv";
    }

    my $command = "cd $dir; zip $zipfile ".
                  "$file-$date-header.csv ".
                  "$file-$date-detail.csv";

    system($command) and die "$command failed\n";

    unlink "$file-$date-header.csv",
           "$file-$date-detail.csv";

    if ( $url =~ /^http/i ) {

      my $ua = new LWP::UserAgent;
      my $res = $ua->request( POST( $url,
                                    'Content_Type' => 'form-data',
                                    'Content' => [ 'username' => $username,
                                                   'pass'     => $password,
                                                   'custid'   => $username,
                                                   'clicode'  => $opt{clicode},
                                                   'file1'    => [ $zipfile ],
                                                 ],
                                  )
                            );

      die "upload failed: ". $res->status_line. "\n"
        unless $res->is_success;

    } elsif ( $url =~ /^ftp:\/\/([\w\.]+)(\/.*)$/i ) {

      my($hostname, $path) = ($1, $2);

      my $ftp = new Net::FTP($hostname, Passive=>1)
        or die "can't connect to $hostname: $@\n";
      $ftp->login($username, $password)
        or die "can't login to $hostname: ". $ftp->message."\n";
      unless ( $ftp->cwd($path) ) {
        my $msg = "can't cd $path on $hostname: ". $ftp->message. "\n";
        ( $path eq '/' ) ? warn $msg : die $msg;
      }
      $ftp->binary
        or die "can't set binary mode on $hostname\n";

      $ftp->put($zipfile)
        or die "can't put $zipfile: ". $ftp->message. "\n";

      $ftp->quit;

    } else {
      die "unknown scheme in URL $url\n";
    }

  }
  else { #not billco

    my $targetnum = $opt{targetnum};
    my $upload_target = FS::upload_target->by_key($targetnum)
      or die "FTP target $targetnum not found\n";

    $dir .= "/target$targetnum";
    chdir($dir);

    my $file  = $agentnum ? "agentnum$agentnum" : 'spool'; #.csv

    unless ( -f "$dir/$file.csv" ) {
      warn "$me $dir/$file.csv not found\n" if $DEBUG > 1;
      $log->debug("finish ($dir/$file.csv not found)");
      $dbh->commit or die $dbh->errstr if $oldAutoCommit;
      return;
    }

    rename "$dir/$file.csv", "$dir/$file-$date.csv";

    if ( $opt{'handling'} eq 'bridgestone' ) {

      my $prefix = $conf->config('bridgestone-prefix', $agentnum);
      unless ( $prefix ) {
        warn "$me agent $agentnum has no bridgestone-prefix, skipped\n";
        $dbh->commit or die $dbh->errstr if $oldAutoCommit;
        return;
      }

      my $seq = $conf->config('bridgestone-batch_counter', $agentnum) || 1;

      # extract zip code
      join(' ',$conf->config('company_address', $agentnum)) =~ 
        /(\d{5}(\-\d{4})?)\s*$/;
      my $ourzip = $1 || ''; #could be an explicit option if really needed
      $ourzip  =~ s/\D//;
      my $newfile = sprintf('%s_%s_%0.6d.dat', 
                            $prefix,
                            time2str('%Y%m%d', time),
                            $seq);
      warn "copying spool to $newfile\n" if $DEBUG;

      my ($in, $out);
      open $in, '<', "$dir/$file-$date.csv" 
        or die "unable to read $file-$date.csv\n";
      open $out, '>', "$dir/$newfile" or die "unable to write $newfile\n";
      #header--not sure how much of this generalizes at all
      my $head = sprintf(
        "%-6s%-4s%-27s%-6s%0.6d%-5s%-9s%-9s%-7s%0.8d%-7s%0.6d\n",
        ' COMP:', 'VISP', '', ',SEQ#:', $seq, ',ZIP:', $ourzip, ',VERS:1.1',
        ',RUNDT:', time2str('%m%d%Y', $^T),
        ',RUNTM:', time2str('%H%M%S', $^T),
      );
      warn "HEADER: $head" if $DEBUG;
      print $out $head;

      my $rows = 0;
      while( <$in> ) {
        print $out $_;
        $rows++;
      }

      #trailer
      my $trail = sprintf(
        "%-6s%-4s%-27s%-6s%0.6d%-7s%0.9d%-9s%0.9d\n",
        ' COMP:', 'VISP', '', ',SEQ:', $seq,
        ',LINES:', $rows+2, ',LETTERS:', $rows,
      );
      warn "TRAILER: $trail" if $DEBUG;
      print $out $trail;

      close $in;
      close $out;

      my $zipfile = sprintf('%s_%0.6d.zip', $prefix, $seq);
      my $command = "cd $dir; zip $zipfile $newfile";
      warn "compressing to $zipfile\n$command\n" if $DEBUG;
      system($command) and die "$command failed\n";

      my $error = $upload_target->put($zipfile);
      if ( $error ) {
        foreach ( qw ( header detail ) ) {
          rename "$dir/$file-$date-$_.csv",
                 "$dir/$file-$_.csv";
          die $error;
        }
      }

      send_email(
        prepare_report('bridgestone-confirm_template',
          {
            agentnum=> $agentnum,
            zipfile => $zipfile,
            prefix  => $prefix,
            seq     => $seq,
            rows    => $rows,
          }
        )
      );

      $seq++;
      warn "setting batch counter to $seq\n" if $DEBUG;
      $conf->set('bridgestone-batch_counter', $seq, $agentnum);

    } elsif ( $opt{'handling'} eq 'ics' ) {

      my ($basename, $regfile, $bigfile);
      $basename = sprintf('c%sc1', time2str('%m%d', time));
      $regfile = $basename . 'i.txt'; # for "regular" (short) invoices
      $bigfile = $basename . 'b.txt'; # for "big" invoices

      warn "copying spool to $regfile, $bigfile\n" if $DEBUG;

      my ($in, $reg, $big); #filehandles
      my %count = (B => 0, 1 => 0, 2 => 0); # number of invoices
      my %sum = (B => 0, R => 0); # total of charges field
      open $in, '<', "$dir/$file-$date.csv" 
        or die "unable to read $file-$date.csv\n";

      open $reg, '>', "$dir/$regfile" or die "unable to write $regfile\n";
      open $big, '>', "$dir/$bigfile" or die "unable to write $bigfile\n";

      while (my $line = <$in>) {
        chomp($line);
        my $tag = substr($line, -1, 1, '');
        my $charge = substr($line, 252, 10);
        if ( $tag eq 'B' ) {
          print $big $line, "\n";
          $count{B}++;
          $sum{B} += $charge;
        } else {
          print $reg $line, "\n";
          $count{$tag}++;
          $sum{R} += $charge;
        }
      }
      close $in;
      close $reg;
      close $big;

      # zip up all three files for transport
      my $zipfile = "$basename" . '.zip';
      my $command = "cd $dir; zip $zipfile $regfile $bigfile";
      system($command) and die "'$command' failed\n";

      # upload them, unless we're using email, in which case 
      # the zip file will ride along with the report.  yes, this 
      # kind of defeats the purpose of the upload_target interface,
      # but at least we have a place to store the configuration.
      my $error = '';
      if ( $upload_target->protocol ne 'email' ) {
        $error = $upload_target->put("$dir/$zipfile");
      }

      # create the report
      for (values %sum) {
        $_ = sprintf('%.2f', $_);
      }

      my %report = prepare_report('ics-confirm_template',
        {
          agentnum  => $agentnum,
          count     => \%count,
          sum       => \%sum,
          error     => $error,
        }
      );
      if ( $upload_target->protocol eq 'email' ) {
        $report{'to'} =
          join('@', $upload_target->username, $upload_target->hostname);
        $report{'subject'} = $upload_target->subject;
        $report{'mimeparts'} = [
          { Path        => "$dir/$zipfile",
            Type        => 'application/zip',
            Encoding    => 'base64',
            Filename    => $zipfile,
            Disposition => 'attachment',
          }
        ];
      }
      $error = send_email(%report);

      if ( $error ) {
        # put the original spool file back
        rename "$dir/$file-$date.csv", "$dir/$file.csv";
        die $error;
      }
 
    } else { # not bridgestone or ics

      # this is the usual case

      my $error = $upload_target->put("$file-$date.csv");
      if ( $error ) {
        rename "$dir/$file-$date.csv", "$dir/$file.csv";
        die $error;
      }

    }

  } #opt{handling}

  $log->debug('finish', agentnum => $agentnum);

  $dbh->commit or die $dbh->errstr if $oldAutoCommit;
  '';

}

=item prepare_report CONFIG PARAMS

Retrieves the config value named CONFIG, parses it as a Text::Template,
extracts "to" and "subject" headers, and returns a hash that can be passed
to L<FS::Misc::send_email>.

PARAMS is a hashref to be passed to C<fill_in>.  It must contain 
'agentnum' to look up the per-agent config.

=cut

# we used it twice, so it's now a subroutine

sub prepare_report {

  my ($config, $params) = @_;
  my $agentnum = $params->{agentnum};
  my $conf = FS::Conf->new;

  my $template = join("\n", $conf->config($config, $agentnum));
  if (!$template) {
    warn "$me agent $agentnum has no $config, no email report sent\n";
    return;
  }

  my $tmpl_obj = Text::Template->new(
    TYPE => 'STRING', SOURCE => $template
  );
  my $content = $tmpl_obj->fill_in( HASH => $params );
  my ($head, $body) = split("\n\n", $content, 2);
  $head =~ /^subject:\s*(.*)$/im;
  my $subject = $1;

  $head =~ /^to:\s*(.*)$/im;
  my $to = $1;

  (
    to      => $to,
    from    => $conf->config('invoice_from', $agentnum),
    subject => $subject,
    body    => $body,
  );

}

1;
