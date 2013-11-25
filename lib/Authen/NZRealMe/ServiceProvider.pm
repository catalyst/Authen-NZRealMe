package Authen::NZRealMe::ServiceProvider;

use strict;
use warnings;

require XML::LibXML;
require XML::LibXML::XPathContext;
require XML::Generator;
require Crypt::OpenSSL::X509;
require HTTP::Response;

use URI::Escape  qw(uri_escape uri_unescape);
use Digest::MD5  qw(md5_hex);
use POSIX        qw(strftime);
use Date::Parse  qw();
use File::Spec   qw();

use WWW::Curl::Easy qw(
    CURLOPT_URL
    CURLOPT_POST
    CURLOPT_HTTPHEADER
    CURLOPT_POSTFIELDS
    CURLOPT_SSLCERT
    CURLOPT_SSLKEY
    CURLOPT_SSL_VERIFYPEER
    CURLOPT_WRITEDATA
    CURLOPT_WRITEHEADER
);

use constant DATETIME_BEFORE => -1;
use constant DATETIME_EQUAL  => 0;
use constant DATETIME_AFTER  => 1;


my $metadata_from_file    = undef;
my $metadata_filename     = 'metadata-sp.xml';
my $signing_cert_filename = 'sp-sign-crt.pem';
my $signing_key_filename  = 'sp-sign-key.pem';
my $ssl_cert_filename     = 'sp-ssl-crt.pem';
my $ssl_key_filename      = 'sp-ssl-key.pem';


my $ns_md       = [ md => 'urn:oasis:names:tc:SAML:2.0:metadata' ];
my $ns_ds       = [ ds => 'http://www.w3.org/2000/09/xmldsig#'   ];
my $ns_saml     = [ saml  => 'urn:oasis:names:tc:SAML:2.0:assertion' ];
my $ns_samlp    = [ samlp => 'urn:oasis:names:tc:SAML:2.0:protocol'  ];
my $ns_soap_env = [ 'SOAP-ENV' => 'http://schemas.xmlsoap.org/soap/envelope/' ];

my $urn_nameid_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

my $soap_action = 'http://www.oasis-open.org/committees/security';


sub new {
    my $class = shift;

    my $self = bless {
        skip_signature_check => 0,
        @_
    }, $class;

    my $conf_dir = $self->{conf_dir} or die "conf_dir not set\n";
    $self->{conf_dir} = File::Spec->rel2abs($conf_dir);

    $self->_load_metadata();

    return $self;
}


sub new_defaults {
    my $class = shift;

    my $self = bless {
        @_,
    }, $class;

    return $self;
}


sub conf_dir               { shift->{conf_dir};               }
sub entity_id              { shift->{entity_id};              }
sub url_single_logout      { shift->{url_single_logout};      }
sub url_assertion_consumer { shift->{url_assertion_consumer}; }
sub organization_name      { shift->{organization_name};      }
sub organization_url       { shift->{organization_url};       }
sub contact_company        { shift->{contact_company};        }
sub contact_first_name     { shift->{contact_first_name};     }
sub contact_surname        { shift->{contact_surname};        }
sub skip_signature_check   { shift->{skip_signature_check};   }
sub _x                     { shift->{x};                      }
sub nameid_format          { return $urn_nameid_format;       }
sub signing_cert_pathname  { shift->{conf_dir} . '/' . $signing_cert_filename; }
sub signing_key_pathname   { shift->{conf_dir} . '/' . $signing_key_filename;  }
sub ssl_cert_pathname      { shift->{conf_dir} . '/' . $ssl_cert_filename;     }
sub ssl_key_pathname       { shift->{conf_dir} . '/' . $ssl_key_filename;      }

sub idp {
    my $self = shift;

    return $self->{idp} if $self->{idp};

    $self->{idp} = Authen::NZRealMe->class_for('identity_provider')->new(
        conf_dir => $self->conf_dir()
    );
}


sub generate_saml_id {
    my($self, $type) = @_;
    return ('a'..'f')[rand(6)]  # id string must start with a letter
           . md5_hex( join(',', "$self", $type, time(), rand(), $$) );
}


sub generate_certs {
    my($class, $conf_dir, %args) = @_;

    Authen::NZRealMe->class_for('sp_cert_factory')->generate_certs(
        $conf_dir, %args
    );
}


sub build_new {
    my($class, %opt) = @_;

    my $conf_dir  = $opt{conf_dir} or die "conf_dir not specified\n";
    my $conf_path = $class->_metadata_pathname($conf_dir);

    my $self = -r $conf_path
               ? $class->new(conf_dir => $opt{conf_dir})
               : $class->new_defaults(conf_dir => $opt{conf_dir});

    my $args = eval {
        Authen::NZRealMe->class_for('sp_builder')->build($self);
    };
    if($@) {
        print STDERR "$@";
        exit 1;
    }
    return unless $args;

    $self->{$_} = $args->{$_} foreach keys %$args;

    open my $fh, '>', $conf_path or die "open(>$conf_path): $!";
    print $fh $self->metadata_xml(), "\n";

    return $self;
}


sub make_bundle {
    my $class = shift;

    my $sp = $class->new(@_);
    return Authen::NZRealMe->class_for('sp_builder')->make_bundle($sp);
}


sub _load_metadata {
    my $self = shift;

    my $params = $metadata_from_file || $self->_read_metadata_from_file;

    $self->{$_} = $params->{$_} foreach keys %$params;
}


sub _read_metadata_from_file {
    my $self = shift;

    my $metadata_file = $self->_metadata_pathname;
    die "File does not exist: $metadata_file\n" unless -e $metadata_file;

    my $parser = XML::LibXML->new();
    my $doc    = $parser->parse_file( $metadata_file );
    my $xc     = XML::LibXML::XPathContext->new( $doc->documentElement() );

    $xc->registerNs( @$ns_md );

    my %params;
    foreach (
        [ id                     => q{/md:EntityDescriptor/@ID} ],
        [ entity_id              => q{/md:EntityDescriptor/@entityID} ],
        [ url_single_logout      => q{/md:EntityDescriptor/md:SPSSODescriptor/md:SingleLogoutService/@Location} ],
        [ url_assertion_consumer => q{/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location} ],
        [ organization_name      => q{/md:EntityDescriptor/md:Organization/md:OrganizationName} ],
        [ organization_url       => q{/md:EntityDescriptor/md:Organization/md:OrganizationURL} ],
        [ contact_company        => q{/md:EntityDescriptor/md:ContactPerson/md:Company} ],
        [ contact_first_name     => q{/md:EntityDescriptor/md:ContactPerson/md:GivenName} ],
        [ contact_surname        => q{/md:EntityDescriptor/md:ContactPerson/md:SurName} ],
    ) {
        $params{$_->[0]} = $xc->findvalue($_->[1]);
    }

    $metadata_from_file = \%params;
}


sub _metadata_pathname {
    my $self     = shift;
    my $conf_dir = shift;

    $conf_dir ||= $self->conf_dir or die "conf_dir not set";
    return $conf_dir . '/' . $metadata_filename;
}


sub new_request {
    my $self = shift;

    my $req = Authen::NZRealMe->class_for('authen_request')->new($self, @_);
    return $req;
}


sub _signing_cert_pem_data {
    my $self = shift;

    return $self->{signing_cert_pem_data} if $self->{signing_cert_pem_data};

    my $path = $self->signing_cert_pathname
        or die "No path to signing certificate file";

    my $cert_data = do {
        local($/) = undef; # slurp mode
        open my $fh, '<', $path or die "open($path): $!";
        <$fh>;
    };

    $cert_data =~ s{\r\n}{\n}g;
    $cert_data =~ s{\A.*?^-+BEGIN CERTIFICATE-+\n}{}sm;
    $cert_data =~ s{^-+END CERTIFICATE-+\n?.*\z}{}sm;

    return $cert_data;
}


sub metadata_xml {
    my $self = shift;

    return $self->_to_xml_string();
}


sub _sign_xml {
    my($self, $xml, $target_id) = @_;

    my $signer = $self->_signer();

    return $self->_signer->sign($xml, $target_id);
}


sub sign_query_string {
    my($self, $qs) = @_;

    $qs .= '&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1';

    my $signer = $self->_signer();

    my $sig = $signer->rsa_signature( $qs, '' );

    return $qs . '&Signature=' . uri_escape( $sig );
}


sub _signer {
    my($self) = @_;

    my $key_path = $self->signing_key_pathname
        or die "No path to signing key file";

    return Authen::NZRealMe->class_for('xml_signer')->new(
        key_file => $key_path,
    );
}


sub resolve_artifact {
    my($self, %args) = @_;

    my $artifact = $args{artifact}
        or die "Need artifact from SAMLart URL parameter\n";

    if($artifact =~ m{\bSAMLart=(.*?)(?:&|$)}) {
        $artifact = uri_unescape($1);
    }

    die "Can't resolve artifact without original request ID\n"
        unless $args{request_id};

    my $request   = Authen::NZRealMe->class_for('resolution_request')->new($self, $artifact);
    my $url       = $request->destination_url;
    my $soap_body = $request->soap_request;

    my $headers = [
        'User-Agent: Authen-NZRealMe/' . $Authen::NZRealMe::VERSION,
        'Content-Type: text/xml',
        'SOAPAction: http://www.oasis-open.org/committees/security',
        'Content-Length: ' . length($soap_body),
    ];


    my $resp = $self->_https_post($url, $headers, $soap_body);

    die "Artifact resolution failed:\n" . $resp->as_string
        unless $resp->is_success;

    return $self->_verify_assertion($resp->content, %args);
}


sub _https_post {
    my($self, $url, $headers, $body) = @_;

    my $curl = new WWW::Curl::Easy;

    $curl->setopt(CURLOPT_URL,        $url);
    $curl->setopt(CURLOPT_POST,       1);
    $curl->setopt(CURLOPT_HTTPHEADER, $headers);
    $curl->setopt(CURLOPT_POSTFIELDS, $body);
    $curl->setopt(CURLOPT_SSLCERT,    $self->ssl_cert_pathname);
    $curl->setopt(CURLOPT_SSLKEY,     $self->ssl_key_pathname);
    $curl->setopt(CURLOPT_SSL_VERIFYPEER, 0);

    my($resp_body, $resp_head);
    open (my $body_fh, ">", \$resp_body);
    $curl->setopt(CURLOPT_WRITEDATA, $body_fh);
    open (my $head_fh, ">", \$resp_head);
    $curl->setopt(CURLOPT_WRITEHEADER, $head_fh);

    my $resp;
    my $retcode = $curl->perform;
    if($retcode == 0) {
        my($status, @head_lines) = split(/\r?\n/, $resp_head);
        my($protocol, $code, $message) = split /\s+/, $status, 3;
        my $headers = [ map { split /:\s+/, $_, 2 } @head_lines];

        $resp = HTTP::Response->new($code, $message, $headers, $resp_body);
    }
    else {
        $resp = HTTP::Response->new(
            500, 'Error', [], $curl->strerror($retcode)." ($retcode)\n"
        );
    }

    return $resp;
}


sub _verify_assertion {
    my($self, $xml, %args) = @_;

    my $parser = XML::LibXML->new();
    my $doc    = $parser->parse_string( $xml );
    my $xc     = XML::LibXML::XPathContext->new( $doc->documentElement() );

    $xc->registerNs( @$ns_soap_env );
    $xc->registerNs( @$ns_saml );
    $xc->registerNs( @$ns_samlp );


    # Check for SOAP error

    if(my($error) = $xc->findnodes('//SOAP-ENV:Fault')) {
        my $code   = $xc->findvalue('./SOAP-ENV:faultcode',   $error) || 'Unknown';
        my $string = $xc->findvalue('./SOAP-ENV:faultstring', $error) || 'Unknown';
        die "SOAP protocol error:\n  Fault Code: $code\n  Fault String: $string\n";
    }


    # Extract the SAML result code

    my $response = $self->_build_resolution_response($xc, $xml);
    return $response if $response->is_error;


    # Look for the SAML Response Subject payload

    my($subject) = $xc->findnodes(
        '//samlp:ArtifactResponse/samlp:Response/saml:Assertion/saml:Subject'
    ) or die "Unable to find SAML Subject element in:\n$xml\n";


    # We have a SAML assertion, make sure it's signed

    my $idp  = $self->idp;
    $self->_verify_assertion_signature($idp, $xml);


    # Confirm that subject is valid for our SP

    $self->_check_subject_confirmation($xc, $subject, $args{request_id});


    # Check that it was generated by the expected IdP

    my $idp_entity_id = $idp->entity_id;
    my $from_sp = $xc->findvalue('./saml:NameID/@NameQualifier', $subject) || '';
    die "SAML assertion created by '$from_sp', expected '$idp_entity_id'\n$xml\n"
        if $from_sp ne $idp_entity_id;


    # Check that it's intended for our SP

    my $sp_entity_id  = $self->entity_id;
    my $for_sp = $xc->findvalue('./saml:NameID/@SPNameQualifier', $subject) || '';
    die "SAML assertion created for '$for_sp', expected '$sp_entity_id'\n$xml\n"
        if $for_sp ne $sp_entity_id;


    # Look for Conditions on the assertion

    $self->_check_conditions($xc);  # will die on failure


    # Make sure it's in the expected format

    my $nameid_format = $self->nameid_format();
    my $format = $xc->findvalue('./saml:NameID/@Format', $subject) || '';
    die "Unrecognised NameID format '$format', expected '$nameid_format'\n$xml\n"
        if $format ne $nameid_format;


    # Check the logon strength (if required)

    my $strength = $xc->findvalue(
        q{//samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef}
    ) || '';
    $response->set_logon_strength($strength);
    if($args{logon_strength}) {
        $strength = Authen::NZRealMe->class_for('logon_strength')->new($strength);
        $strength->assert_match($args{logon_strength}, $args{strength_match});
    }

    # Extract the FLT

    my $flt = $xc->findvalue(
        q{//samlp:Response/saml:Assertion/saml:Subject/saml:NameID}
    ) or die "Can't find NameID element in response:\n$xml\n";

    $flt =~ s{\s+}{}g;

    $response->set_flt($flt);

    return $response;
}


sub _verify_assertion_signature {
    my($self, $idp, $xml) = @_;

    my $skip_type = $self->skip_signature_check;
    return if $skip_type > 1;

    eval {
        $idp->verify_signature($xml);
    };
    return unless $@;  # Signature was good

    if($skip_type) {
        warn "WARNING: Continuing after signature verification failure "
           . "(skip_signature_check is enabled)\n$@\n";
        return;
    }

    die $@;   # Re-throw the exception
}


sub _build_resolution_response {
    my($self, $xc, $xml) = @_;

    my $response = Authen::NZRealMe->class_for('resolution_response')->new($xml);

    my($status_code) = $xc->findnodes(
        '//samlp:ArtifactResponse/samlp:Response/samlp:Status/samlp:StatusCode'
    ) or die "Could not find a SAML status code\n$xml\n";

    # Recurse down to find the most specific status code

    while(
        my($child_code) = $xc->findnodes('./samlp:StatusCode', $status_code)
    ) {
        $status_code = $child_code;
    }

    my($urn) = $xc->findvalue('./@Value', $status_code)
        or die "Couldn't find 'Value' attribute for StatusCode\n$xml\n";

    $response->set_status_urn($urn);

    return $response if $response->is_success;

    my $message = $xc->findvalue(
        '//samlp:ArtifactResponse/samlp:Response/samlp:Status/samlp:StatusMessage'
    ) || '';
    $message =~ s{^\[.*\]}{};    # Strip off [SP EntityID] prefix
    $response->set_status_message($message) if $message;

    return $response
}


sub _check_subject_confirmation {
    my($self, $xc, $subject, $request_id) = @_;

    my $xml = $subject->toString();

    my($conf_data) = $xc->findnodes(
        './saml:SubjectConfirmation/saml:SubjectConfirmationData',
        $subject
    ) or die "SAML assertion does not contain SubjectConfirmationData\n$xml\n";


    # Check that it's a reply to our request

    my $response_to = $xc->findvalue('./@InResponseTo', $conf_data) || '';
    die "SAML response to unexpected request ID\n"
        . "Original:    '$request_id'\n"
        . "Response To: '$response_to'\n$xml\n" if $request_id ne $response_to;

    # Check that it has not expired

    my $now = $self->now_as_iso();

    if(my($end_time) = $xc->findvalue('./@NotOnOrAfter', $conf_data)) {
        if($self->_compare_times($now, $end_time) != DATETIME_BEFORE) {
            die "SAML assertion SubjectConfirmationData expired at '$end_time'\n";
        }
    }

}


sub _check_conditions {
    my($self, $xc) = @_;

    my($conditions) = $xc->findnodes(
        '//samlp:ArtifactResponse/samlp:Response/saml:Assertion/saml:Conditions'
    ) or return;

    my $xml = $conditions->toString();

    my $now = $self->now_as_iso();

    if(my($start_time) = $xc->findvalue('./@NotBefore', $conditions)) {
        if($self->_compare_times($start_time, $now) != DATETIME_BEFORE) {
            die "SAML assertion not valid until '$start_time'\n";
        }
    }

    if(my($end_time) = $xc->findvalue('./@NotOnOrAfter', $conditions)) {
        if($self->_compare_times($now, $end_time) != DATETIME_BEFORE) {
            die "SAML assertion not valid after '$end_time'\n";
        }
    }

    foreach my $condition ($xc->findnodes('./saml:*', $conditions)) {
        my($name)  = $condition->localname();
        my $method = "_check_condition_$name";
        die "Unimplemented condition: '$name'" unless $self->can($method);
        $self->$method($xc, $condition);
    }

    return;  # no problems were encountered
}


sub _check_condition_AudienceRestriction {
    my($self, $xc, $condition) = @_;

    my $entity_id = $self->entity_id;
    my $audience  = $xc->findvalue('./saml:Audience', $condition)
        or die "Can't find target audience in: " . $condition->toString();

    die "SAML assertion only valid for audience '$audience' (expected '$entity_id')"
        if $audience ne $entity_id;
}


sub _compare_times {
    my($self, $date1, $date2) = @_;

    foreach ($date1, $date2) {
        s/\s+//g;
        die "Invalid timestamp '$_'\n"
            unless /\A\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ(.*)\z/s;
        die "Non-UTC dates are not supported: '$_'" if $1;
    }

    return $date1 cmp $date2;
}


sub _to_xml_string {
    my $self = shift;

    my $ns_md_uri = $ns_md->[1];   # Used as default namespace, so no prefix required
    my $x = XML::Generator->new(':pretty',
        namespace => [ '#default' => $ns_md_uri ],
    );
    $self->{x} = $x;

    my $xml = $x->EntityDescriptor(
        {
            entityID    => $self->entity_id,
            validUntil  => $self->_valid_until_datetime,
        },
        $self->_gen_sp_sso_descriptor(),
        $self->_gen_organization(),
        $self->_gen_contact(),
    );
    $xml =~ s{ _xml_lang_attribute="}{ xml:lang="}sg;
    return $xml;
}


sub _valid_until_datetime {
    my $self = shift;

    my $x509 = Crypt::OpenSSL::X509->new_from_file( $self->signing_cert_pathname );
    my $date_time = $x509->notAfter;
    my $utime = Date::Parse::str2time($date_time);
    return strftime('%FT%TZ', gmtime($utime) );
}


sub _gen_sp_sso_descriptor {
    my $self = shift;
    my $x    = $self->_x;

    return $x->SPSSODescriptor(
        {
            AuthnRequestsSigned        => 'true',
            WantAssertionsSigned       => 'true',
            protocolSupportEnumeration => 'urn:oasis:names:tc:SAML:2.0:protocol',
        },
        $self->_gen_signing_key(),
        #$self->_gen_svc_logout(),      # No longer required
        $self->_name_id_format(),
        $self->_gen_svc_assertion_consumer(),
    );
}


sub _gen_signing_key {
    my $self = shift;
    my $x    = $self->_x;

    return $x->KeyDescriptor(
        {
            use => 'signing',
        },
        $x->KeyInfo($ns_ds,
            $x->X509Data($ns_ds,
                $x->X509Certificate($ns_ds,
                    $self->_signing_cert_pem_data(),
                ),
            ),
        ),
    );
}


sub _name_id_format {
    my $self = shift;
    my $x    = $self->_x;

    return $x->NameIDFormat(
        $self->nameid_format
    );
}


sub _gen_svc_logout {
    my $self = shift;
    my $x    = $self->_x;

    my $single_logout_url = $self->url_single_logout or return;
    return $x->SingleLogoutService(
        {
            Binding          => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            Location         => $single_logout_url,
        },
    );
}


sub _gen_svc_assertion_consumer {
    my $self = shift;
    my $x    = $self->_x;

    return $x->AssertionConsumerService(
        {
            Binding          => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
            Location         => $self->url_assertion_consumer,
            index            => 0,
            isDefault        => 'true',
        },
    );
}


sub _gen_organization {
    my $self = shift;
    my $x    = $self->_x;

    return $x->Organization(
        $x->OrganizationName(
            {
                _xml_lang_attribute  => 'en-us',
            },
            $self->organization_name
        ),
        $x->OrganizationDisplayName(
            {
                _xml_lang_attribute  => 'en-us',
            },
            $self->organization_name
        ),
        $x->OrganizationURL(
            {
                _xml_lang_attribute  => 'en-us',
            },
            $self->organization_url
        ),
    );
}


sub _gen_contact {
    my $self = shift;
    my $x    = $self->_x;

    my $have_contact = $self->contact_company
                       || $self->contact_first_name
                       || $self->contact_surname;

    return() unless $have_contact;

    return $x->ContactPerson(
        {
            contactType      => 'technical',
        },
        $x->Company  ($self->contact_company    || ''),
        $x->GivenName($self->contact_first_name || ''),
        $x->SurName  ($self->contact_surname    || ''),
    );
}


sub now_as_iso {
    return strftime('%FT%TZ', gmtime());
}


1;


__END__

=head1 NAME

Authen::NZRealMe::ServiceProvider - Class representing the local SAML2 Service Provider

=head1 DESCRIPTION

This class is used to represent the local SAML2 Service Provider which will be
used to access the NZ igovt logon service Identity Provider.  In normal use, an
object of this class is initialised from the F<metadata-sp.xml> in the
configuration directory.  This class can also be used to generate that metadata
file.

=head1 METHODS

=head2 new

Constructor.  Should not be called directly.  Instead, call:

  Authen::NZRealMe->service_provider( args );

The following options are recognised:

=over 4

=item conf_dir => '/path/to/directory'

The C<conf_dir> parameter B<must> be provided.  It specifies the full pathname
of the directory containing SP and IdP metadata files as well as certificate
and key files for request signing and mutual-SSL.

=item skip_signature_check => [ 0 | 1 | 2 ]

This (seldom used) option allows you to turn off verification of digital
signatures in the assertions returned from the IdP.  The default value is 0 -
meaning B<signatures will be checked>.

If set to 1, a failed signature check will result in a warning to STDERR but
further processing of the assertion will continue.  This mode is useful if the
signing certificate is scheduled to be replaced on the IdP.  Enabling this
option allows you to update your metadata before or after the scheduled change
without needing to coordinate your timing exactly with the IdP service.

Setting this option to 2 will completely skip signature checks (i.e. no errors
or warnings will be generated).

=back

=head2 new_defaults

Alternative constructor which is called to set up some sensible defaults when
generating metadata.

=head2 conf_dir

Accessor for the C<conf_dir> parameter passed in to the constructor.

=head2 entity_id

Accessor for the C<entityID> parameter in the Service Provider metadata file.

=head2 url_single_logout

Accessor for the C<SingleLogoutService> parameter in the Service Provider
metadata file.

=head2 url_assertion_consumer

Accessor for the C<AssertionConsumerService> parameter in the Service Provider
metadata file.

=head2 organization_name

Accessor for the C<OrganizationName> component of the C<Organization> parameter in the
Service Provider metadata file.

=head2 organization_url

Accessor for the C<OrganizationURL> component of the C<Organization> parameter in the
Service Provider metadata file.

=head2 contact_company

Accessor for the C<Company> component of the C<ContactPerson> parameter in the
Service Provider metadata file.

=head2 contact_first_name

Accessor for the C<GivenName> component of the C<ContactPerson> parameter in the
Service Provider metadata file.

=head2 contact_surname

Accessor for the C<SurName> component of the C<ContactPerson> parameter in the
Service Provider metadata file.

=head2 signing_cert_pathname

Accessor for the pathname of the Service Provider's signing certificate.  This
will always be the file F<sp-sign-crt.pem> in the configuration directory.

=head2 signing_key_pathname

Accessor for the pathname of the Service Provider's signing key.  This will
always be the file F<sp-sign-key.pem> in the configuration directory.

=head2 ssl_cert_pathname

Accessor for the pathname of the Service Provider's mutual SSL certificate.
This will always be the file F<sp-ssl-crt.pem> in the configuration directory.

=head2 ssl_key_pathname

Accessor for the pathname of the Service Provider's mutual SSL private key.
This will always be the file F<sp-sign-crt.pem> in the configuration directory.

=head2 idp

Accessor for an object representing the Identity Provider (See:
L<Authen::NZRealMe::IdentityProvider>.

=head2 nameid_format

Returns a string URN representing the format of the NameID (Federated LogonTag
- FLT) requested/expected from the Identity Provider.

=head2 generate_saml_id

Used by the request classes to generate a unique identifier for each request.
It accepts one argument, being a string like 'AuthenRequest' to identify the
type of request.

=head2 generate_certs

Called by the C<< nzigovt make-certs >> command to run an interactive Q&A
session to generate either self-signed certificates or Certificate Signing
Requests (CSRs).  Delegates to L<Authen::NZRealMe::ServiceProvider::CertFactory>

=head2 build_new

Called by the C<< nzigovt make-meta >> command to run an interactive Q&A
session to initialise or edit the contents of the Service Provider metadata
file.  Delegates to L<Authen::NZRealMe::ServiceProvider::Builder>

=head2 make_bundle

Called by the C<< nzigovt make-bundle >> command to create a zip archive of
the files needed by the IdP.  The archive will include the SP metadata and
certificate files.  Delegates to L<Authen::NZRealMe::ServiceProvider::Builder>

=head2 new_request( options )

Creates a new L<Authen::NZRealMe::AuthenRequest> object.  The caller would
typically use the C<as_url> method of the request to redirect the client to the
Identity Provider's single logon service.  The request object's C<request_id>
method should be used to get the request ID and save it in session state for
use later during artifact resolution.

The C<new_request> method does not B<require> any arguments, but accepts the
following optional key => value pairs:

=over 4

=item allow_create => boolean

Controls whether the user should be allowed to create a new account on the IdP.
Default: false.

=item force_auth => boolean

Controls whether the user will be forced to log in, rather than allowing the
reuse of an existing logon session on the IdP.  Default: true.

=item auth_strength => string

The logon strength required.  May be supplied as a URN, or as keyword ('low',
'mod', 'sms', etc).  See L<Authen::NZRealMe::LogonStrength> for constants.
Default: 'low'.

=item relay_state => string

User-supplied string value that will be returned as a URL parameter to the
assertion consumer service.as_url

=back

=head2 metadata_xml

Serialises the current Service Provider config parameters to a SAML2
EntityDescriptor metadata document.

=head2 sign_query_string

Used by the L<Authen::NZRealMe::AuthenRequest> class to create a digital
signature for the AuthnRequest HTTP-Redirect URL.

=head2 resolve_artifact

Takes an artifact (either the whole URL or just the C<SAMLart> parameter) and
contacts the Identity Provider to resolve it to an FLT.  Parameters (including
the original request_id) must be supplied as key => value pairs, for example:

  my $resp = $sp->resolve_artifact(
      artifact        => $framework->param('SAMLart'),
      request_id      => $framework->state('igovt_request_id'),
      logon_strength  => 'low',        # optional
      strength_match  => 'minimum',    # optional - default: 'minimum'
  );

The assertion returned by the Identity Provider will be validated and its
contents returned as an L<Authen::NZRealMe::ResolutionResponse> object.  If an
unexpected error occurs while resolving the artifact or while validating the
resulting assertion, an exception will be thrown.  Expected error conditions
(eg: timeouts, user presses 'Cancel' etc) will not throw an exception, but will
return a response object that can be interrogated to determine the nature of
the error.  The calling application may wish to log the expected errors with
a severity of 'WARN' or 'INFO'.

=head2 now_as_iso

Convenience method returns the current time (UTC) formatted as an ISO date/time
string.


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


