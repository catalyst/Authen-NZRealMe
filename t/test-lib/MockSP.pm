package MockSP;

use 5.010;
use strict;
use warnings;
use autodie;

use parent 'Authen::NZRealMe::ServiceProvider';

use AuthenNZRealMeTestHelper;

use MIME::Base64    qw(decode_base64);
use HTTP::Response  qw();


sub resolve_artifact {
    my $self = shift;
    $self->{_test_request_log_} = [];
    return $self->SUPER::resolve_artifact(@_);
}


sub test_request_log {
    my $self = shift;
    return @{ $self->{_test_request_log_} };
}


sub _https_post {
    my($self, $url, $headers, $soap_body) = @_;

    push @{ $self->{_test_request_log_} }, $soap_body;

    my $content;
    if (my $response_file = $url =~ /ws.test.logon.fakeme.govt.nz/) {
        $content = $self->_icms_response($soap_body);
    }
    else {
        $content = $self->_saml_response($soap_body);
    }

    my $resp = HTTP::Response->new(200, 'OK', [], $content );
    return $resp;
}


sub idp_signer {
    my($self, %options) = @_;

    my $conf_dir = $self->conf_dir;

    return Authen::NZRealMe->class_for('xml_signer')->new(
        pub_cert_file => $conf_dir . '/idp-assertion-sign-crt.pem',
        key_file      => $conf_dir . '/idp-assertion-sign-key.pem',
        %options,
    );
}


sub _saml_response {
    my($self, $soap_body) = @_;

    my($artifact) = $soap_body =~ m{
        <\w+:Artifact>
          ([^<]+)
        </\w+:Artifact>
    }x;

    my $bytes = decode_base64($artifact);
    my($type_code, $index, $source_id, $file_name, $target_id, $algorithm) = unpack('n n a20 C/A* C/A* C/A*', $bytes);

    my $file = test_data_file($file_name);
    my $unsigned_xml = $self->_read_file($file);
    my $signer = $self->idp_signer(algorithm => 'algorithm_' . $algorithm);

    return $signer->sign($unsigned_xml, $target_id, include_x509 => 1);
}

my $ns_soap    = [ soap   => 'http://www.w3.org/2003/05/soap-envelope' ];
my $ns_wsu     = [ wsu   => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' ];
my $ns_wsse    = [ wsse  => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' ];
my $ns_wst     = [ wst   => "http://docs.oasis-open.org/ws-sx/ws-trust/200512" ];
my $ns_saml    = [ saml  => 'urn:oasis:names:tc:SAML:2.0:assertion' ];
my $ns_ds      = [ ds    => 'http://www.w3.org/2000/09/xmldsig#'   ];
my $ns_dsig    = [ dsig    => 'http://www.w3.org/2000/09/xmldsig#'   ];
my $ns_wsa     = [ wsa   => "http://www.w3.org/2005/08/addressing" ];
my $ns_icms    = [ iCMS  => "urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0" ];

sub _icms_response {
    my($self, $soap_body) = @_;

    my($request_number) = $soap_body =~ m{
        <fakeToken>identity-(\d+)</fakeToken>
    }x;
    my $algorithm = 'sha1';
    my $file = test_data_file("icms-response-${request_number}.unsigned.xml");
    my $unsigned_xml = $self->_read_file($file);

    # First sign the Body
    my $signer_b = $self->_signer(id_attr => 'wsu:Id');
    my $unsigned_doc = $signer_b->_xml_to_dom($unsigned_xml);
    my $unsigned_xc  = XML::LibXML::XPathContext->new( $unsigned_doc );
    foreach my $ns ( ($ns_soap, $ns_wsse, $ns_wsu, $ns_wst, $ns_saml) ) {
        $unsigned_xc->registerNs( @$ns );
    }
    my $target_id = $unsigned_xc->findvalue(q{/soap:Envelope/soap:Body/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion/@ID});
    my $signer_body = $self->idp_signer(algorithm => 'algorithm_' . $algorithm);

    my $signed_body = $signer_body->sign($unsigned_xml, $target_id);
    # Then sign the multiple parts of the Header as the Identity Provider
    my $signer_header = $self->idp_signer(
        algorithm => 'algorithm_' . $algorithm,
        id_attr   => 'wsu:Id',
    );

    my $doc = $signer_header->_xml_to_dom($signed_body);
    my $xc  = XML::LibXML::XPathContext->new( $doc );

    foreach my $ns ( ($ns_soap, $ns_wsse, $ns_wsu, $ns_wst, $ns_saml, $ns_ds, $ns_dsig, $ns_wsa, $ns_icms) ) {
        $xc->registerNs( @$ns );
    }

    my @signed_parts = (
        {
            element     => 'wsu:Timestamp',
            namespaces  => ['wsse', 'soap'],
        },
        {
            element     => 'soap:Body',
        },
        {
            element     => 'wsa:To',
            namespaces  => ['soap'],
        },
        {
            element     => 'wsa:MessageID',
            namespaces  => ['soap'],
        },
        {
            element     => 'wsa:RelatesTo',
            namespaces  => ['soap'],
        },
        {
            element     => 'wsa:Action',
            namespaces  => ['soap'],
        },
    );
    foreach (@signed_parts) {
        my $value = $_->{id} = $xc->findvalue(q{//} . $_->{element} . q{/@wsu:Id});
    }
    my $signed_response = $signer_header->sign_multiple_targets($signed_body, \@signed_parts);
    return $signed_response;
}


sub wind_back_clock {
    my $self = shift;
    $self->{_stopped_clock_time_} = shift;
}


sub now_as_iso {
    my $self = shift;

    return $self->{_stopped_clock_time_} if $self->{_stopped_clock_time_};
    return $self->SUPER::now_as_iso();
}


1;
