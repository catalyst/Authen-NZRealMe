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


my %metadata_cache;
my $signing_cert_filename = 'sp-sign-crt.pem';
my $signing_key_filename  = 'sp-sign-key.pem';
my $ssl_cert_filename     = 'sp-ssl-crt.pem';
my $ssl_key_filename      = 'sp-ssl-key.pem';
my $icms_wsdl_filename    = 'icms-description.xml';


my $ns_md       = [ md    => 'urn:oasis:names:tc:SAML:2.0:metadata' ];
my $ns_ds       = [ ds    => 'http://www.w3.org/2000/09/xmldsig#'   ];
my $ns_saml     = [ saml  => 'urn:oasis:names:tc:SAML:2.0:assertion' ];
my $ns_samlp    = [ samlp => 'urn:oasis:names:tc:SAML:2.0:protocol'  ];
my $ns_soap_env = [ 'SOAP-ENV' => 'http://schemas.xmlsoap.org/soap/envelope/' ];
my $ns_xpil     = [ xpil  => "urn:oasis:names:tc:ciq:xpil:3" ];
my $ns_xal      = [ xal   => "urn:oasis:names:tc:ciq:xal:3"   ];
my $ns_xnl      = [ xnl   => "urn:oasis:names:tc:ciq:xnl:3" ];
my $ns_ct       = [ ct    => "urn:oasis:names:tc:ciq:ct:3"  ];
my $ns_soap     = [ soap  => "http://www.w3.org/2003/05/soap-envelope" ];
my $ns_wsse     = [ wsse  => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ];
my $ns_wsu      = [ wsu   => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ];
my $ns_wst      = [ wst   => "http://docs.oasis-open.org/ws-sx/ws-trust/200512/" ];
my $ns_wsa      = [ wsa   => "http://www.w3.org/2005/08/addressing" ];
my $ns_ec       = [ ec    => "http://www.w3.org/2001/10/xml-exc-c14n#" ];
my $ns_icms     = [ iCMS  => "urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0" ];
my $ns_wsdl     = [ wsdl  => 'http://schemas.xmlsoap.org/wsdl/' ];
my $ns_soap_12  = [ soap  => 'http://schemas.xmlsoap.org/wsdl/soap12/' ];
my $ns_wsam     = [ wsam  => 'http://www.w3.org/2007/05/addressing/metadata' ];

my @ivs_namespaces  = ( $ns_xpil, $ns_xnl, $ns_ct, $ns_xal );
my @avs_namespaces  = ( $ns_xpil, $ns_xal );
my @icms_namespaces = ( $ns_ds, $ns_saml, $ns_icms, $ns_wsse, $ns_wsu, $ns_wst, $ns_soap  );
my @wsdl_namespaces = ( $ns_wsdl, $ns_soap_12, $ns_wsam );

my %urn_nameid_format = (
    login     => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    assertion => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    unspec    => 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified',
);

my %urn_attr_name = (
    fit         => 'urn:nzl:govt:ict:stds:authn:attribute:igovt:IVS:FIT',
    ivs         => 'urn:nzl:govt:ict:stds:authn:safeb64:attribute:igovt:IVS:Assertion:Identity',
    avs         => 'urn:nzl:govt:ict:stds:authn:safeb64:attribute:NZPost:AVS:Assertion:Address',
    icms_token  => 'urn:nzl:govt:ict:stds:authn:safeb64:attribute:opaque_token',
);

my $soap_action = 'http://www.oasis-open.org/committees/security';


sub new {
    my $class = shift;

    my $self = bless {
        type                  => 'login',
        skip_signature_check  => 0,
        @_
    }, $class;

    my $conf_dir = $self->{conf_dir} or die "conf_dir not set\n";
    $self->{conf_dir} = File::Spec->rel2abs($conf_dir);

    $self->_check_type();

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
sub type                   { shift->{type};                   }
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
sub nameid_format          { return $urn_nameid_format{ shift->type };         }
sub signing_cert_pathname  { shift->{conf_dir} . '/' . $signing_cert_filename; }
sub signing_key_pathname   { shift->{conf_dir} . '/' . $signing_key_filename;  }
sub ssl_cert_pathname      { shift->{conf_dir} . '/' . $ssl_cert_filename;     }
sub ssl_key_pathname       { shift->{conf_dir} . '/' . $ssl_key_filename;      }

sub idp {
    my $self = shift;

    return $self->{idp} if $self->{idp};

    $self->{idp} = Authen::NZRealMe->class_for('identity_provider')->new(
        conf_dir  => $self->conf_dir(),
        type      => $self->type,
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


sub build_meta {
    my($class, %opt) = @_;

    Authen::NZRealMe->class_for('sp_builder')->build($class, %opt);
}


sub _read_file {
    my($self, $filename) = @_;

    local($/) = undef; # slurp mode
    open my $fh, '<', $filename or die "open($filename): $!";
    my $data = <$fh>;
    return $data;
}


sub _write_file {
    my($self, $filename, $data) = @_;

    open my $fh, '>', $filename or die "open(>$filename): $!";
    print $fh $data;

    close($fh) or die "close(>$filename): $!";
}


sub make_bundle {
    my($class, %opt) = @_;

    my $conf_dir = $opt{conf_dir};
    foreach my $type (qw(login assertion)) {
        my $conf_path = $class->_metadata_pathname($conf_dir, $type);
        if(-r $conf_path) {
          my $sp = $class->new(
              conf_dir  => $conf_dir,
              type      => $type,
          );
          my $zip = Authen::NZRealMe->class_for('sp_builder')->make_bundle($sp);
          print "Created metadata bundle for '$type' IDP at:\n$zip\n\n";
        }
    }
}


sub _check_type {
    my $self = shift;

    my $type = $self->type;
    if($type ne 'login' and $type ne 'assertion') {
        warn qq{Unknown service type.\n} .
             qq{  Got: "$type"\n} .
             qq{  Expected: "login" or "assertion"\n};
    }
}


sub _load_metadata {
    my $self = shift;

    my $cache_key = $self->conf_dir . '-' . $self->type;
    my $params = $metadata_cache{$cache_key} || $self->_read_metadata_from_file;

    $self->{$_} = $params->{$_} foreach keys %$params;
}


sub _read_metadata_from_file {
    my $self = shift;

    my $metadata_file = $self->_metadata_pathname;
    die "File does not exist: $metadata_file\n" unless -e $metadata_file;

    my $xc = $self->_xpath_context_dom($metadata_file, $ns_md);

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

    my $cache_key = $self->conf_dir . '-' . $self->type;
    $metadata_cache{$cache_key} = \%params;

    my $icms_pathname = $self->_icms_wsdl_pathname;

    if ( $self->{type} eq 'assertion' && -e $icms_pathname ){
        $self->_parse_icms_wsdl;
    }

    return \%params;
}

sub _parse_icms_wsdl {
    my ($self) = @_;

    my $icms_pathname = $self->_icms_wsdl_pathname;
    die "No ICMS WSDL file in config directory" unless -e $icms_pathname;
    my $description = $self->_read_file($icms_pathname);
    my $dom = XML::LibXML->load_xml( string => $description );
    my $xpc = XML::LibXML::XPathContext->new();
    foreach my $ns ( @wsdl_namespaces ) {
        $xpc->registerNs(@$ns);
    }
    my $result = {};
    foreach my $type ( 'Issue', 'Validate' ){
        $result->{$type} = {
            url       => $dom->findvalue('./wsdl:definitions/wsdl:service[@name="igovtContextMappingService"]/wsdl:port[@name="'.$type.'"]/soap:address/@location'),
            operation => $dom->findvalue('./wsdl:definitions/wsdl:portType[@name="'.$type.'"]/wsdl:operation/wsdl:input/@wsam:Action'),
        };
    }

    my $cache_key = $self->conf_dir . '-' . $self->type . '-icms';
    $metadata_cache{$cache_key} = $result;
}

sub _metadata_pathname {
    my $self     = shift;
    my $conf_dir = shift;
    my $type     = shift;

    $type //= $self->type;

    $conf_dir ||= $self->conf_dir or die "conf_dir not set";

    return $conf_dir . '/metadata-' . $type . '-sp.xml';
}

sub _icms_wsdl_pathname {
    my $self     = shift;
    my $conf_dir = shift;
    my $type     = shift;

    $type //= $self->type;

    $conf_dir ||= $self->conf_dir or die "conf_dir not set";

    return $conf_dir . '/'.$icms_wsdl_filename;
}

sub icms_method_data {
    my $self = shift;
    my $method = shift;

    my $cache_key = $self->conf_dir . '-' . $self->type . '-icms';

    my $methods = $metadata_cache{$cache_key} || $self->_parse_icms_wsdl;

    return $methods->{$method};
}

sub _xpath_context_dom {
    my($self, $source, @namespaces) = @_;

    my $parser = XML::LibXML->new();
    my $doc    = $source =~ /<.*>/
                 ? $parser->parse_string( $source )
                 : $parser->parse_file( $source );
    my $xc     = XML::LibXML::XPathContext->new( $doc->documentElement() );

    foreach my $ns ( @namespaces ) {
        $xc->registerNs( @$ns );
    }

    return $xc;
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

    my $cert_data = $self->_read_file($path);

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

    return $signer->sign($xml, $target_id);
}


sub sign_query_string {
    my($self, $qs) = @_;

    $qs .= '&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1';

    my $signer = $self->_signer();

    my $sig = $signer->rsa_signature( $qs, '' );

    return $qs . '&Signature=' . uri_escape( $sig );
}


sub _signer {
    my($self, $id_attr) = @_;

    my $key_path = $self->signing_key_pathname
        or die "No path to signing key file";

    my %options = (pub_cert_file => $self->signing_cert_pathname,key_file => $key_path);
    $options{id_attr} = $id_attr if $id_attr;

    return Authen::NZRealMe->class_for('xml_signer')->new(
        key_file => $key_path,
        %options
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
        'User-Agent: Authen-NZRealMe/' . ($Authen::NZRealMe::VERSION // '0.0'),
        'Content-Type: text/xml',
        'SOAPAction: http://www.oasis-open.org/committees/security',
        'Content-Length: ' . length($soap_body),
    ];


    my $content;
    if($args{_from_file_}) {
        $content =  $self->_read_file($args{_from_file_});
    }
    else {
        my $http_resp = $self->_https_post($url, $headers, $soap_body);

        die "Artifact resolution failed:\n" . $http_resp->as_string
            unless $http_resp->is_success;

        $content = $http_resp->content;

        if($args{_to_file_}) {
            $self->_write_file($args{_to_file_}, $content);
        }
    }

    my $response = $self->_verify_assertion($content, %args);

    if($self->type eq 'assertion'  and  $args{resolve_flt}) {
         $self->_resolve_flt($response, %args);
    }

    return $response;
}

sub _resolve_flt {
    my($self, $idp_response, %args) = @_;

    my $opaque_token = $idp_response->_icms_token();

    my $request   = Authen::NZRealMe->class_for('icms_resolution_request')->new($self, $opaque_token);

    my $method = $self->icms_method_data('Validate');

    my $request_data = $request->request_data;

    my $headers = [
        'User-Agent: Authen-NZRealMe/' . ($Authen::NZRealMe::VERSION // '0.0'),
        'Content-Type: text/xml',
        'SOAPAction: ' . $method->{operation},
        'Content-Length: ' . length($request_data),
    ];

    my $response = $self->_https_post($request->destination_url, $headers, $request_data);

    my $content = $response->content;

    if ( !$response->is_success ){
        my $xc = $self->_xpath_context_dom($content, $ns_soap, $ns_icms);
        # Grab and output the SOAP error explanation, if present.
        if(my($error) = $xc->findnodes('//soap:Fault')) {
            my $code       = $xc->findvalue('./soap:Code/soap:Value',       $error) || 'Unknown';
            my $string     = $xc->findvalue('./soap:Reason/soap:Text',      $error) || 'Unknown';
            die "ICMS error:\n  Fault Code: $code\n  Fault String: $string";
        }
        die "Error resolving FLT\n  Response code:$response->code\n  Message:$response->message";
    }

    if($args{_to_file_}) {
            $self->_write_file($args{_to_file_}, $content) if $response->is_success;
    }

    my $flt = $self->_extract_flt($content);
    $idp_response->set_flt($flt);
}

sub _extract_flt {
    my($self, $xml, %args) = @_;
    my $xc = $self->_xpath_context_dom($xml, @icms_namespaces);
    # We have a SAML assertion, make sure it's signed
    my $idp = $self->idp;
    # ICMS responses use wsu:Id's for their ID attribute, and are (for some
    # bizarre reason) signed with the key the login service uses.
    eval {
        my $verifier = Authen::NZRealMe->class_for('xml_signer')->new(
            pub_cert_text => $idp->login_cert_pem_data(),
            id_attr       => 'wsu:Id',
        );
        $verifier->verify($xml);
    };
    if($@) {
        die "Failed to verify signature on assertion from IdP:\n  $@\n$xml";
    }
    return $xc->findvalue(q{/soap:Envelope/soap:Body/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion/saml:Subject/saml:NameID});
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
        $resp_head =~ s/\A(?:HTTP\/1\.1 100 Continue)?[\r\n]*//; # Remove any '100' responses and/or leading newlines
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

    my $xc = $self->_xpath_context_dom($xml, $ns_soap_env, $ns_saml, $ns_samlp);

    # Check for SOAP error

    if(my($error) = $xc->findnodes('//SOAP-ENV:Fault')) {
        my $code   = $xc->findvalue('./faultcode',   $error) || 'Unknown';
        my $string = $xc->findvalue('./faultstring', $error) || 'Unknown';
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
    die "SAML assertion created by '$from_sp', expected '$idp_entity_id'. Assertion follows:\n$xml\n"
        if $from_sp ne $idp_entity_id;


    # Check that it's intended for our SP

    if($self->type eq 'login') {  # Not provided by assertion IdP
        my $sp_entity_id  = $self->entity_id;
        my $for_sp = $xc->findvalue('./saml:NameID/@SPNameQualifier', $subject) || '';
        die "SAML assertion created for '$for_sp', expected '$sp_entity_id'\n$xml\n"
            if $for_sp ne $sp_entity_id;
    }

    # Look for Conditions on the assertion

    $self->_check_conditions($xc);  # will die on failure


    # Make sure it's in the expected format

    my $nameid_format = $self->nameid_format();
    my $format = $xc->findvalue('./saml:NameID/@Format', $subject) || '';
    die "Unrecognised NameID format '$format', expected '$nameid_format'\n$xml\n"
        if $format ne $nameid_format;


    # Check the logon strength (if required)

    if($self->type eq 'login') {  # Not needed for assertion IdP
        my $strength = $xc->findvalue(
            q{//samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef}
        ) || '';
        $response->set_logon_strength($strength);
        if($args{logon_strength}) {
            $strength = Authen::NZRealMe->class_for('logon_strength')->new($strength);
            $strength->assert_match($args{logon_strength}, $args{strength_match});
        }
    }

    # Extract the payload

    if($self->type eq 'login') {
        $self->_extract_login_payload($response, $xc);
    }
    elsif($self->type eq 'assertion') {
        $self->_extract_assertion_payload($response, $xc);
    }

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
    $response->set_service_type( $self->type );

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


sub _extract_login_payload {
    my($self, $response, $xc) = @_;

    # Extract the FLT

    my $flt = $xc->findvalue(
        q{//samlp:Response/saml:Assertion/saml:Subject/saml:NameID}
    ) or die "Can't find NameID element in response:\n" . $response->xml . "\n";

    $flt =~ s{\s+}{}g;

    $response->set_flt($flt);
}


sub _extract_assertion_payload {
    my($self, $response, $xc) = @_;

    # Extract the asserted attributes

    my $attribute_selector =
        q{//samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute};

    foreach my $attr ( $xc->findnodes($attribute_selector) ) {
        my $name  = $xc->findvalue('./@Name', $attr) or next;
        my $value = $xc->findvalue('./saml:AttributeValue', $attr) || '';
        if($name =~ /:safeb64:/) {
            $value = MIME::Base64::decode_base64url($value);
        }
        if($name eq $urn_attr_name{fit}) {
            $response->set_fit($value);
        }
        elsif($name eq $urn_attr_name{ivs}) {
            $self->_extract_ivs_details($response, $value);
        }
        elsif($name eq $urn_attr_name{avs}) {
            $self->_extract_avs_details($response, $value);
        }
        elsif($name eq $urn_attr_name{icms_token}) {
            $self->_extract_icms_token($response, $value);
        }
    }

    #$response->set_flt($flt);
}


sub _extract_ivs_details {
    my($self, $response, $xml) = @_;

    my $xc = $self->_xpath_context_dom($xml, @ivs_namespaces);

    my($dd, $mm, $yyyy);

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:BirthInfo/xpil:BirthInfoElement[@xpil:Type='BirthDay']},
        sub { $dd = shift; }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:BirthInfo/xpil:BirthInfoElement[@xpil:Type='BirthMonth']},
        sub { $mm = shift; }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:BirthInfo/xpil:BirthInfoElement[@xpil:Type='BirthYear']},
        sub { $yyyy = shift; }
    );

    if($dd && $mm && $yyyy) {
        $response->set_date_of_birth("$yyyy-$mm-$dd");
    }

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:BirthInfo/xpil:BirthPlaceDetails/xal:Locality/xal:NameElement},
        sub { $response->set_place_of_birth(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:BirthInfo/xpil:BirthPlaceDetails/xal:Country/xal:NameElement},
        sub { $response->set_country_of_birth(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:PartyName/xnl:PersonName/xnl:NameElement[@xnl:ElementType='LastName']},
        sub { $response->set_surname(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:PartyName/xnl:PersonName/xnl:NameElement[@xnl:ElementType='FirstName']},
        sub { $response->set_first_name(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:PartyName/xnl:PersonName/xnl:NameElement[@xnl:ElementType='MiddleName']},
        sub { $response->set_mid_names(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xpil:PersonInfo/@xpil:Gender},
        sub { $response->set_gender(shift); }
    );

}


sub _extract_avs_details {
    my($self, $response, $xml) = @_;

    my $xc = $self->_xpath_context_dom($xml, @avs_namespaces);

    $self->_xc_extract($xc,
        q{/xpil:Party/xal:Addresses/xal:Address[1]/xal:Premises/xal:NameElement[@NameType="NZUnit"]},
        sub { $response->set_address_unit(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xal:Addresses/xal:Address[1]/xal:Thoroughfare/xal:NameElement[@NameType="NZNumberStreet"]},
        sub { $response->set_address_street(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xal:Addresses/xal:Address[1]/xal:Locality/xal:NameElement[@NameType="NZSuburb"]},
        sub { $response->set_address_suburb(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xal:Addresses/xal:Address[1]/xal:Locality/xal:NameElement[@NameType="NZTownCity"]},
        sub { $response->set_address_town_city(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xal:Addresses/xal:Address[1]/xal:PostCode/xal:Identifier[@Type="NZPostCode"]},
        sub { $response->set_address_postcode(shift); }
    );

    $self->_xc_extract($xc,
        q{/xpil:Party/xal:Addresses/xal:Address[1]/xal:RuralDelivery/xal:Identifier[@Type="NZRuralDelivery"]},
        sub { $response->set_address_rural_delivery(shift); }
    );

}


sub _extract_icms_token {
    my($self, $response, $xml) = @_;

    $response->_set_icms_token($xml);
}


sub _xc_extract {
    my($self, $xc, $selector, $handler) = @_;

    my @match = $xc->findnodes($selector);
    if(@match > 1) {
        die "Error: found multiple matches (" . @match . ") for selector:\n  '$selector'";
    }
    elsif(@match == 1) {
        $handler->( $match[0]->to_literal, $match[0] );
    }
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

    # apply fixups
    $xml =~ s{ _xml_lang_attribute="}{ xml:lang="}sg;
    $xml =~ s{\s*<NoIndentContent.*?>(.*?)</NoIndentContent.*?>\s*}
             {_unindent_element_content($1)}sge;

    return $xml;
}


sub _unindent_element_content {
    my($content) = @_;

    $content =~ s{^\s+}{}mg;
    return $content;
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
                    $x->NoIndentContent( $self->_signing_cert_pem_data() ),
                ),
            ),
        ),
    );
}


sub _name_id_format {
    my $self = shift;
    my $x    = $self->_x;

    my @formats = (
        $x->NameIDFormat( $self->nameid_format )
    );

    if($self->type eq 'assertion') {
        push @formats, $x->NameIDFormat( $urn_nameid_format{unspec} );
    }

    return @formats;
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

This class is used to represent the local SAML2 SP (Service Provider) which
will be used to access the NZ RealMe Login service IdP (Identity Provider) or
the NZ RealMe Assertion service IdP.  In normal use, an object of this class is
initialised from the F<metadata-sp.xml> in the configuration directory.  This
class can also be used to generate that metadata file.

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

=item type => ( "login" | "assertion" )

Indicate whether you wish to communicate with the "login" service or the
"assertion" service (for identity information).  Default: "login".

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

Accessor for an object representing the Identity Provider for the selected
service type ("login" or "assertion").  See:
L<Authen::NZRealMe::IdentityProvider>.

=head2 nameid_format

Returns a string URN representing the format of the NameID (Federated Logon Tag
- FLT) requested/expected from the Identity Provider.

=head2 generate_saml_id

Used by the request classes to generate a unique identifier for each request.
It accepts one argument, being a string like 'AuthenRequest' to identify the
type of request.

=head2 generate_certs

Called by the C<< nzrealme make-certs >> command to run an interactive Q&A
session to generate either self-signed certificates or Certificate Signing
Requests (CSRs).  Delegates to L<Authen::NZRealMe::ServiceProvider::CertFactory>

=head2 build_meta

Called by the C<< nzrealme make-meta >> command to run an interactive Q&A
session to initialise or edit the contents of the Service Provider metadata
file.  Delegates to L<Authen::NZRealMe::ServiceProvider::Builder>

=head2 make_bundle

Called by the C<< nzrealme make-bundle >> command to create a zip archive of
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

Controls whether the user should be allowed to create a new account on the
"login" service IdP.  Not used when talking to the "assertion service".
Default: false.

=item force_auth => boolean

Controls whether the user will be forced to log in, rather than allowing the
reuse of an existing logon session on the IdP.  Not useful, as the login
service ignores this option anyway.  Default: true.

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
contacts the Identity Provider to resolve it to a set of attributes.  An
artifact from the login server will only provide an 'FLT' attribute.  An
artifact from the assertion server will provide identity and/or address
attributes.

Parameters (including the original request_id) must be supplied as key => value
pairs, for example:

  my $resp = $sp->resolve_artifact(
      artifact        => $framework->param('SAMLart'),
      request_id      => $framework->state('login_request_id'),
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

Recognised parameter names are:

=over 4

=item artifact

Either the whole URL of the client request to the ACS, or just the C<SAMLart>
parameter from the querystring.

=item request_id

The C<request_id> returned in the original call to C<new_request>.  Your
application will need to store this in session state when initiating the
dialogue with the IdP and retrieve it from state when resolving the artifact.

=item logon_strength

Optional parameter which may be used to check that the response from the logon
service matches your application's logon strength requirements.  Specify as a
URN string or a word (e.g.: "low", "moderate").  If not provided, no check will
be performed.

=item strength_match

If a logon_strength was specified, this parameter will determine how the values
will be matched.  Provide either "minimum" (the default) or "exact".

=item resolve_flt

When resolving an artifact from the assertion service, you can provide this
option with a true value to indicate that the opaque token should be resolved
to an FLT.  If this option is not set, only the attributes from the assertion
service will be returned and no attempt will be made to connect to the iCMS
service.

=back

=head2 now_as_iso

Convenience method returns the current time (UTC) formatted as an ISO date/time
string.


=head1 SEE ALSO

See L<Authen::NZRealMe> for documentation index.


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2010-2013 Enrolment Services, New Zealand Electoral Commission

Written by Grant McLean E<lt>grant@catalyst.net.nzE<gt>

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut


