package Authen::NZigovt;

use warnings;
use strict;


=head1 NAME

Authen::NZigovt - Tools for integrating with the New Zealand igovt logon service

=head1 DESCRIPTION

This module provides an API for integrating your application with the New
Zealand igovt logon service using SAML 2.0 messaging.

The distribution also includes a command-line tool called C<nzigovt> which can
be used for:

=over 4

=item *

creating/editing the Service Provider metadata file

=item *

generating AuthnRequest URLs

=item *

decoding/dumping AuthnRequest URLs

=item *

resolving SAMLart artifact responses and validating the response

=back

See the C<--help> option for more information.

=cut


my %class_map = (
    service_provider    => 'Authen::NZigovt::ServiceProvider',
    identity_provider   => 'Authen::NZigovt::IdentityProvider',
    xml_signer          => 'Authen::NZigovt::XMLSig',
    sp_builder          => 'Authen::NZigovt::ServiceProvider::Builder',
    resolution_request  => 'Authen::NZigovt::ResolutionRequest',
    resolution_response => 'Authen::NZigovt::ResolutionResponse',
    authen_request      => 'Authen::NZigovt::AuthenRequest',
    logon_strength      => 'Authen::NZigovt::LogonStrength',
);


sub class_for {
    my($class, $key) = @_;
    my $module = $class_map{$key} or die "No class defined for '$key'";
    $module =~ s{::}{/}g;
    require $module . '.pm';
    return $class_map{$key};
}


sub register_class {
    my($class, $key, $package) = @_;
    $class_map{$key} = $package;
}


sub run_command {
    my $class   = shift;
    my $opt     = shift;
    my $command = shift or die "no command specified\n";

    my $method = '_dispatch_' . $command;
    $method =~ s{[^a-z0-9]+}{_}g;
    die "unrecognised command: '$command'\n" unless $class->can($method);

    $class->$method($opt, @_);
}


sub _dispatch_make_meta {
    my($class, $opt) = @_;

    die "Need --conf-dir option\n" unless $opt->{conf_dir};
    my $sp = $class->class_for('service_provider')->build_new(
        conf_dir => $opt->{conf_dir},
    );
    print "File saved\n" if $sp;
}


sub _dispatch_make_certs {
    my($class, $opt) = @_;

    # TODO
    print "This feature is not yet implemented\n";
    exit 1;
}


sub _dispatch_make_idp_bundle {
    my($class, $opt) = @_;

    # TODO
    print "This feature is not yet implemented\n";
    exit 1;
}


sub _dispatch_make_req {
    my($class, $opt) = @_;

    my $sp = $class->class_for('service_provider')->new(
        conf_dir => $opt->{conf_dir},
    );
    my $req = $sp->new_request(
        allow_create => 0,
    );
    print "Request ID: ", $req->request_id, "\n" if -t 1;
    print $req->as_url, "\n";
}


sub _dispatch_dump_req {
    my $class = shift;
    my $opt   = shift;

    $class->class_for('authen_request')->dump_request(@_);
}


sub _dispatch_resolve {
    my $class      = shift;
    my $opt        = shift;
    my $artifact   = shift or die "Must provide artifact or URL\n";
    my $request_id = shift or die "Must provide ID from original request\n";

    my $sp = $class->class_for('service_provider')->new(
        conf_dir => $opt->{conf_dir},
    );
    my %args = (
        artifact   => $artifact,
        request_id => $request_id,
    );
    $args{logon_strength} = shift if @_;
    $args{strength_match} = shift if @_;
    my $result = eval {
        my $resp = $sp->resolve_artifact(%args);
    };
    if($@) {
        print "Failed to resolve artifact:\n$@";
        exit 1;
    }
    foreach my $key (sort keys %$result) {
        print "$key: $result->{$key}\n";
    }
}

1;


__END__

=head1 SYNOPSIS

Following successful configuration (see L<CONFIGURATION>), authentication
proceeds in two phases.

First, an AuthnRequest is generated and encoded as a URL.  You must arrange
for the user's browser to be redirected to this URL, you must also save the
request ID in your application session state:

  use Authen::NZigovt;

  my $sp = Authen::NZigovt->class_for('service_provider')->new(
      conf_dir => $path_to_config_directory,
  );
  my $req = $sp->new_request(
      allow_create => 0,         # set to 1 for initial registration
  );

  $my_app->set_state(igovt_request_id => $req->request_id);

  $framework->redirect($req->request_id);

Once the user has logged in they will be redirected back to your application
and passed an 'artifact'.  You will use this API to resolve the artifact and
validate the resulting assertion.  The result will be a response object which
you can query to get the 'FLT' (Federated Logon Tag) on success, or details of
any error which may have occurred.

It is your responsibility to create a persistent association in your
application data store between your user record and the igovt FLT for that
user.

  my $resp = eval {
      $sp->resolve_artifact(
          artifact   => $req->param('SAMLart'),
          request_id => $my_app->get_state('igovt_request_id'),
      );
  };
  if($@) {
      # handle catastrophic failures (e.g.: malformed response) here
  }
  if($resp->is_success) {
      $my_app->set_state(igovt_flt => $resp->flt);
      # ... redirect to main menu etc
  }
  elsif($resp->is_timeout) {
      # Present logon screen again with message
  }
  elsif($resp->is_cancel) {
      # Present logon screen again with message
  }
  elsif($resp->is_not_registered) {
      # Only happens if allow_create set to false
      # and user has a logon - but not for our site
  }
  else {
      # Some other failure occurred, user might like to try again later.
      # Should present $resp->status_message to user and also give contact
      # details for igovt Help Desk
  }

Note: there are two different categories of 'error': the C<resolve_artifact()>
method might throw an exception (caught by eval, details in $@); or a response
object might be returned but with C<< $resp->is_success >> set to false.  The
details of an exception should be logged, but not displayed back to the user.
In the event that your application displays the contents of
C<< $resp->status_message >> you should ensure that you apply appropriate HTML
escaping.

For more details, see L<Authen::NZigovt::ServiceProvider>.


=head1 CONFIGURATION

This module is configuration-driven - you simply need to specify the path to
the config directory and it picks up everything it needs to talk to the NZ
igovt logon service Identity Provider from metadata files and
certificate/key-pair files used for signing/encryption.

The names of the files in the config directory are hard-coded so you just need
to point the module at the right directory.  The filenames are:

=over 4

=item metadata-sp.xml

This file contains config parameters for the 'Service Provider' - your end of
the authentication dialog.  You can generate or edit this file interactively
from the command-line with the command:

  nzigovt --conf-dir /path/to/conf/dir make-meta

The directory must already exist and must already contain the signing key-pair
files (described below).

Note: You can't simply edit the XML metadata file, because a digital signature
is added when the file is saved.

Once you have generated the SP metadata file you will need to provide it to the
NZ igovt logon service to install at their end.  You will need to generate
separate metadata files for each of your development, staging and production
environments.

=item metadata-idp.xml

The IdP or Identity Provider metadata file will be provided to you by the NZ
igovt logon service.  You will simply need to copy it to the config directory
and give it the correct name.

=item sp-sign-crt.pem

This certificate file is used for generating digital signatures for the SP
metadata file and SAML authentication requests.  For your initial integration
with the igovt logon service development IdP ('MTS'), certificate key-pair
files will be provided to you.  For staging (ITE) and production, you will need
to generate your own and provide the certificate files (not the private key
files) to the igovt logon service.

=item sp-sign-key.pem

This private key is paired with the F<sp-sign-crt.pem> certificate.

=item sp-ssl-crt.pem

This certificate is used for negotiating an SSL connection on the backchannel
to the IdP artifact resolution service.

=item sp-ssl-key.pem

This private key is paired with the F<sp-ssl-crt.pem> certificate.

=back

=head1 METHODS

=head2 class_for( identifier )

Takes a class identifier (e.g.: C<service_provider>); locates the corresponding
package; loads the package using C<require>; and returns the class name (e.g.:
C<Authen::NZigovt::ServiceProvider>).

=head2 register_class( identifier => package )

Overrides the default class mapping for the specified identifier.  You would
typically use this method when you have written your own class which extends
the behaviour of one of the default classes.

=head2 run_command( command, args )

This method is called by the C<nzigovt> command-line tool, to delegate
tasks to the appropriate classes.  For more information, see
C<< nzigovt --help >>

=cut


=head1 RELATED MODULES

Your application should only need to directly interface with the Service
Provider module (as shown in the L<SYNOPSIS> above).  The service provider will
delegate to other classes as required.  Documentation is available for these
other classes.

=over 4

=item *

L<Authen::NZigovt::ServiceProvider>

=item *

L<Authen::NZigovt::ServiceProvider::Builder>

=item *

L<Authen::NZigovt::IdentityProvider>

=item *

L<Authen::NZigovt::ResolutionRequest>

=item *

L<Authen::NZigovt::AuthenRequest>

=item *

L<Authen::NZigovt::LogonStrength>

=back


=head1 BUGS

Please report any bugs or feature requests to
C<bug-authen-nzigovt at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Authen-NZigovt>.  I will be
notified, and then you'll automatically be notified of progress on your bug as
I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Authen::NZigovt

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Authen-NZigovt>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Authen-NZigovt>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Authen-NZigovt>

=item * Search CPAN

L<http://search.cpan.org/dist/Authen-NZigovt/>

=back


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2010-2011 the New Zealand Electoral Enrolment Centre

Written by Grant McLean E<lt>grant@catalyst.net.nzE<gt>

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

