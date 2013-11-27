package Authen::NZRealMe::ResolutionResponse;

use warnings;
use strict;

my $urn_success = 'urn:oasis:names:tc:SAML:2.0:status:Success';
my $urn_cancel  = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';
my $urn_timeout = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:status:Timeout';
my $urn_not_reg = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';


sub new {
    my $class = shift;
    my $xml   = shift;

    my $self = bless { xml => $xml }, $class;
    return $self;
}


sub xml               { return shift->{xml};                      }
sub service_type      { return shift->{service_type};             }
sub status_urn        { return shift->{status_urn};               }
sub status_message    { return shift->{status_message} || '';     }
sub is_success        { return shift->status_urn eq $urn_success; }
sub is_error          { return shift->status_urn ne $urn_success; }
sub is_timeout        { return shift->status_urn eq $urn_timeout; }
sub is_cancel         { return shift->status_urn eq $urn_cancel;  }
sub is_not_registered { return shift->status_urn eq $urn_not_reg; }
sub flt               { return shift->{flt};                      }
sub fit               { return shift->{fit};                      }
sub logon_strength    { return shift->{logon_strength};           }
sub date_of_birth     { return shift->{date_of_birth};            }
sub place_of_birth    { return shift->{place_of_birth};           }
sub country_of_birth  { return shift->{country_of_birth};         }
sub surname           { return shift->{surname};                  }
sub first_name        { return shift->{first_name};               }
sub mid_names         { return shift->{mid_names};                }
sub gender            { return shift->{gender};                   }
sub address_unit      { return shift->{address_unit};             }
sub address_street    { return shift->{address_street};           }
sub address_suburb    { return shift->{address_suburb};           }
sub address_town_city { return shift->{address_town_city};        }
sub address_postcode  { return shift->{address_postcode};         }

sub set_status_urn {
    my $self = shift;
    $self->{status_urn} = shift or die "No value provided to set_status_urn";
}

sub set_status_message {
    my $self = shift;
    my $msg  = shift or return;
    $self->{status_message} = $msg;
}

sub set_logon_strength {
    my $self = shift;
    $self->{logon_strength} = shift;
}

sub set_flt {
    my $self = shift;
    $self->{flt} = shift or die "No value provided to set_flt";
}

sub set_date_of_birth {
    my($self, $dob) = @_;

    die "Invalid Date of Birth: '$dob'" unless $dob =~ /\A\d\d\d\d-\d\d-\d\d\z/;
    $self->{date_of_birth} = $dob;
}

sub set_service_type            { $_[0]->{service_type}           = $_[1]; }
sub set_fit                     { $_[0]->{fit}                    = $_[1]; }
sub set_place_of_birth          { $_[0]->{place_of_birth}         = $_[1]; }
sub set_country_of_birth        { $_[0]->{country_of_birth}       = $_[1]; }
sub set_surname                 { $_[0]->{surname}                = $_[1]; }
sub set_first_name              { $_[0]->{first_name}             = $_[1]; }
sub set_mid_names               { $_[0]->{mid_names}              = $_[1]; }
sub set_gender                  { $_[0]->{gender}                 = $_[1]; }
sub set_address_unit            { $_[0]->{address_unit}           = $_[1]; }
sub set_address_street          { $_[0]->{address_street}         = $_[1]; }
sub set_address_suburb          { $_[0]->{address_suburb}         = $_[1]; }
sub set_address_town_city       { $_[0]->{address_town_city}      = $_[1]; }
sub set_address_postcode        { $_[0]->{address_postcode}       = $_[1]; }


1;

__END__

=head1 NAME

Authen::NZRealMe::ResolutionResponse - Encapsulates the response from the IdP to
the artifact resolution request

=head1 DESCRIPTION

This package is used by the L<Authen::NZRealMe::ServiceProvider> to represent the
response received from the Identity Provider.

The C<is_success> or C<is_error> methods can be used to determine whether the
user's logon was successful.

On success, the user's FLT can be retrieved using the C<flt> method.

On failure, the URN identifying the exact error can be determined using the
C<status_urn> method.  Convenience methods are also provided for identifying
common error codes that you might want to handle (see: C<is_cancel>,
C<is_timeout>, C<is_not_registered>).

=head1 METHODS

=head2 new

Constructor.  Should not be called directly.  Instead, call the
C<resolve_artifact> method on the service provider object.


=head2 xml

The raw XML response from the IdP.  Useful for logging and diagnostics.


=head2 status_urn

The 'StatusCode' 'Value' (most specific if more than one) in the response from
the IdP.  You probably want to use the convenience methods (such as
C<is_cancel>) rather than querying this directly although in the case of errors
you will want to log this value.


=head2 status_message

In some error cases the IdP will return a human readable message relating to
the error condition.  If provided, you should include it in the error screen
you display to your users.  This routine will return an empty string if the
response contained no message.


=head2 is_success

Returns true if the artifact resolution was successful and an FLT is available.
Returns false otherwise.


=head2 is_error

Returns true if the artifact resolution was not successful.  Returns false
otherwise.


=head2 is_timeout

Returns true if the RealMe Login service timed out waiting for the user to enter
their account details.  After this error, it is safe to present the user with a
"try again" link.


=head2 is_cancel

Returns true if the user selected 'Cancel' or 'Return to agency site' rather
than logging in.  After this error, it is safe to present the user with a "try
again" link.


=head2 is_not_registered

Returns true if the logon was successful but the user's RealMe Login account
has not been associated with this service provider (agency web site).

This situation will only occur if the original authentication request specified
a false value for the C<allow_create> option.  Agency sites which use a
separate flow for the initial sign-up process will need to handle this error.


=head2 flt

If the artifact resolution was successful, use this method to retrieve the
user's FLT - a token uniquely identifying the user.


=head2 logon_strength

The URN indicating the logon strength returned by the IdP.

Note: If you have
specific logon strength requirements, you should specify them using the
C<logon_strength> and C<strength_match> options when calling the service
provider's C<resolve_artifact> method.


=head1 PRIVATE METHODS

The following methods are used by the service provider while setting up the
response object and are not intended for use by the calling application.

=over 4

=item set_status_urn

=item set_status_message

=item set_logon_strength

=item set_flt

=back

=head1 SEE ALSO

See L<Authen::NZRealMe> for documentation index.


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2010-2011 the New Zealand Electoral Enrolment Centre

Written by Grant McLean E<lt>grant@catalyst.net.nzE<gt>

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

