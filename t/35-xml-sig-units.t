#!perl

use strict;
use warnings;

use Test::More;
use FindBin;
use File::Spec;
use lib File::Spec->catdir($FindBin::Bin, 'test-lib');

use AuthenNZRealMeTestHelper;
use Authen::NZRealMe;
use XML::LibXML;


my $dispatcher    = 'Authen::NZRealMe';
my $sig_class     = $dispatcher->class_for('xml_signer');
my $idp_cert_file = File::Spec->catfile(test_conf_dir(), 'idp-assertion-sign-crt.pem');
my $idp_key_file  = File::Spec->catfile(test_conf_dir(), 'idp-assertion-sign-key.pem');

my @ns_ds = (ds => 'http://www.w3.org/2000/09/xmldsig#');

my($verifier, $signer, $xml, $xc, $node, $input, $output, $error);


##############################################################################
# Transform methods

$verifier = $sig_class->new(
    pub_cert_text  => $sig_class->_slurp_file($idp_cert_file),
);
my($tr_by_name, $tr_by_uri, $expected, $parser, $doc, $frag);

ok('1', '===== C14N Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('c14n');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/TR/2001/REC-xml-c14n-20010315');

is(ref($tr_by_name) => 'HASH', 'found c14n by name');
is(ref($tr_by_uri)  => 'HASH', 'found c14n by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$input = q{<Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$expected = q{<Doc xmlns="https://example.com/doc/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title>
</Doc>};

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, $expected, 'canonical output (from string)');

$xc = parse_xml_to_xc($input);
$output = $verifier->_apply_transform($tr_by_name, [$xc, $xc->getContextNode]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== C14N-With-Comments Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('c14n_wc');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments');

is(ref($tr_by_name) => 'HASH', 'found c14n_wc by name');
is(ref($tr_by_uri)  => 'HASH', 'found c14n_wc by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$input = q{<Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$expected = q{<Doc xmlns="https://example.com/doc/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, $expected, 'canonical output (from string)');

$xc = parse_xml_to_xc($input);
$output = $verifier->_apply_transform($tr_by_name, [$xc, $xc->getContextNode]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== C14N Fragment Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('c14n');

$input = q{<box:Container xmlns:box="https://example.com/box/"><Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc></box:Container>};

$expected = q{<Doc xmlns="https://example.com/doc/" xmlns:box="https://example.com/box/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title>
</Doc>};

$xc = parse_xml_to_xc($input, 'doc' => 'https://example.com/doc/');
($frag) = $xc->findnodes('//doc:Doc');
isa_ok($frag => 'XML::LibXML::Element', 'fragment node');

$output = $verifier->_apply_transform($tr_by_name, [$xc, $frag]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== C14N11 Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('c14n11');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/2006/12/xml-c14n11');

is(ref($tr_by_name) => 'HASH', 'found c14n11 by name');
is(ref($tr_by_uri)  => 'HASH', 'found c14n11 by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$input = q{<Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$expected = q{<Doc xmlns="https://example.com/doc/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title>
</Doc>};

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, $expected, 'canonical output (from string)');

$xc = parse_xml_to_xc($input);
$output = $verifier->_apply_transform($tr_by_name, [$xc, $xc->getContextNode]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== C14N11-With-Comments Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('c14n11_wc');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/2006/12/xml-c14n11#WithComments');

is(ref($tr_by_name) => 'HASH', 'found c14n11_wc by name');
is(ref($tr_by_uri)  => 'HASH', 'found c14n11_wc by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$input = q{<Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$expected = q{<Doc xmlns="https://example.com/doc/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, $expected, 'canonical output (from string)');

$xc = parse_xml_to_xc($input);
$output = $verifier->_apply_transform($tr_by_name, [$xc, $xc->getContextNode]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== C14N11 Fragment Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('c14n11');

$input = q{<box:Container xmlns:box="https://example.com/box/"><Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc></box:Container>};

$expected = q{<Doc xmlns="https://example.com/doc/" xmlns:box="https://example.com/box/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title>
</Doc>};

$xc = parse_xml_to_xc($input, 'doc' => 'https://example.com/doc/');
($frag) = $xc->findnodes('//doc:Doc');
isa_ok($frag => 'XML::LibXML::Element', 'fragment node');

$output = $verifier->_apply_transform($tr_by_name, [$xc, $frag]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== EC14N Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('ec14n');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/2001/10/xml-exc-c14n#');

is(ref($tr_by_name) => 'HASH', 'found ec14n by name');
is(ref($tr_by_uri)  => 'HASH', 'found ec14n by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$input = q{<Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$expected = q{<Doc xmlns="https://example.com/doc/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title>
</Doc>};

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, $expected, 'canonical output (from string)');

$xc = parse_xml_to_xc($input);
$output = $verifier->_apply_transform($tr_by_name, [$xc, $xc->getContextNode]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== EC14N-With-Comments Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('ec14n_wc');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/2001/10/xml-exc-c14n#WithComments');

is(ref($tr_by_name) => 'HASH', 'found ec14n_wc by name');
is(ref($tr_by_uri)  => 'HASH', 'found ec14n_wc by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$input = q{<Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$expected = q{<Doc xmlns="https://example.com/doc/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, $expected, 'canonical output (from string)');

$xc = parse_xml_to_xc($input);
$output = $verifier->_apply_transform($tr_by_name, [$xc, $xc->getContextNode]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== EC14N Fragment Canonicalisation =====');

$tr_by_name = $verifier->_find_transform('ec14n');

$input = q{<box:Container xmlns:box="https://example.com/box/"><Doc ccc="three"
bbb="tw&#111;"
aaa="one"
xmlns="https://example.com/doc/">
  <Title>Example Document</Title><!-- a comment -->
</Doc></box:Container>};

$expected = q{<Doc xmlns="https://example.com/doc/" aaa="one" bbb="two" ccc="three">
  <Title>Example Document</Title>
</Doc>};

$xc = parse_xml_to_xc($input, 'doc' => 'https://example.com/doc/');
($frag) = $xc->findnodes('//doc:Doc');
isa_ok($frag => 'XML::LibXML::Element', 'fragment node');

$output = $verifier->_apply_transform($tr_by_name, [$xc, $frag]);
is($output, $expected, 'canonical output (from DOM fragment)');

ok('1', '===== Enveloped Signature =====');

$tr_by_name = $verifier->_find_transform('env_sig');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/2000/09/xmldsig#enveloped-signature');

is(ref($tr_by_name) => 'HASH', 'found env-sig by name');
is(ref($tr_by_uri)  => 'HASH', 'found env-sig by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$input = q{<Doc><dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
  <dsig:SignedInfo>
    <content>Random stuff goes here</content>
    <!-- Nobody would put a comment in their <Signature> -->
  </dsig:SignedInfo>
</dsig:Signature>
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$expected = q{<Doc>
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$output = $verifier->_apply_transform($tr_by_name, $input);
isa_ok($output => 'ARRAY', 'fragment node');
$output = $output->[1];
isa_ok($output => 'XML::LibXML::Element', 'transformed document node');
is($output->toStringEC14N(1), $expected, 'env-sig output (from string)');

$xc = parse_xml_to_xc($input, @ns_ds);
$output = $verifier->_apply_transform($tr_by_name, [$xc, $xc->getContextNode]);
isa_ok($output => 'ARRAY', 'fragment node');
$output = $output->[1];
isa_ok($output => 'XML::LibXML::Element', 'transformed document node');
is($output->toStringEC14N(1), $expected, 'env-sig output (from DOM fragment)');

ok('1', '===== SHA1 Digest =====');

$input = q{<Doc>
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$tr_by_name = $verifier->_find_transform('sha1');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/2000/09/xmldsig#sha1');

is(ref($tr_by_name) => 'HASH', 'found sha1 by name');
is(ref($tr_by_uri)  => 'HASH', 'found sha1 by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, 'zCGTIejOvqGvd6KSmlk4aFOW4Ro=', 'sha1 digest output (from string)');

# No test for sha1 digest with a DOM fragment as input - since any sane
# implementation would use a c14n transform to provide an input string.

ok('1', '===== SHA256 Digest =====');

$input = q{<Doc>
  <Title>Example Document</Title><!-- a comment -->
</Doc>};

$tr_by_name = $verifier->_find_transform('sha256');
$tr_by_uri  = $verifier->_find_transform('http://www.w3.org/2001/04/xmlenc#sha256');

is(ref($tr_by_name) => 'HASH', 'found sha256 by name');
is(ref($tr_by_uri)  => 'HASH', 'found sha256 by URI');
is($tr_by_name->{uri} => $tr_by_uri->{uri}, 'same transform URI');
is($tr_by_name->{method} => $tr_by_uri->{method}, 'same transform method name');

$output = $verifier->_apply_transform($tr_by_name, $input);
is($output, 'WjnmbezTqKqqU7dyvyFO46FwLTa3KBOsklKGLYK4Ge4=',
    'sha256 digest output (from string)'
);

# No test for sha256 digest with a DOM fragment as input - since any sane
# implementation would use a c14n transform to provide an input string.


##############################################################################
# Raw signature methods

my $plaintext       = 'This is some plain text';
my $mismatched_text = 'This is some different plain text';
$signer = $sig_class->new(
    key_text  => $sig_class->_slurp_file($idp_key_file),
);
$verifier = $sig_class->new(
    pub_cert_text  => $sig_class->_slurp_file($idp_cert_file),
);
my($sig_alg, $b64_sig);

ok('1', '===== RSA-SHA1 Signature =====');

$sig_alg = $signer->_find_sig_alg('rsa_sha1');
$b64_sig = $signer->_create_signature($sig_alg, $plaintext);
$b64_sig =~ s/\s+//g;
is(
    $b64_sig,
    'eUrNfCVSosr1PsyofbeC4PyNQZrNuxHE3iw5YBWL8Q39TSvera9Ef6wYSSETSE6j'
    . 'xSXq4JCapAyaj3EcMeu4ksngLmZ+pfrJX/f71gOUAefHCyvr8KNKG4QuUYeL0X'
    . 'Qw0NDnttmfAt4pduVBIkvFMiX6SfFOGz+pmLIZaZg7wIDQkovOEtmpsg/IL4zy'
    . 'v05z52XTMZdXQ+4RAL/YOdzJZ3ow7l6R/q/yZjakMGWIkqWwa7AcL6YPt/Awyw'
    . '50fMtcGii4GVGbOsVUUjHbld4SG1uffzCpOCqqFKKrQWRPjUJuAs9c3L6aqkKf'
    . '80aODokUFhftgM5sMmg3iyNsao2WLw==',
    'created RSA-SHA1 hash signature'
);
ok(
    $verifier->_verify_signature($sig_alg, $plaintext, $b64_sig),
    'verified RSA-SHA1 hash signature'
);
ok(
    !$verifier->_verify_signature($sig_alg, $mismatched_text, $b64_sig),
    'failed to verify mismatched RSA-SHA1 hash signature'
);

ok('1', '===== RSA-SHA256 Signature =====');

$sig_alg = $signer->_find_sig_alg('rsa_sha256');
$b64_sig = $signer->_create_signature($sig_alg, $plaintext);
$b64_sig =~ s/\s+//g;
is(
    $b64_sig,
    'YeR7ga5hEXBD7BL3NTUjReKG09hSp0sWFNs5WpOD3td0nFARedv5Bn6uy1zf2zuW'
    . 'qZos6cyenUERRypZN0QnD5O7M1OmlV/Kpv40UkcMdFqPT/wQP2OHe+YaKXO3b1'
    . 'V9gq1eGhk5wqW51y3Uu6GawKqJj9VZNPD20cDGvTeegtoNjiY3wrFu4G/v6Ro2'
    . 'OaWXOkyQrXN0Ql2TheK4qMV2fklknKsv87H+BCK75+IWHn63LBvavY5kUyvM/2'
    . 'i2n9aoPLkrlVv32dOGFPdN5PE12B8ujcRiywXAHNffYo7s24rbMk/hKAXCG4Ot'
    . '/sh7T+WbBs2Ny8VPq0lgmfnN6o3x0A==',
    'created RSA-SHA256 hash signature'
);
ok(
    $verifier->_verify_signature($sig_alg, $plaintext, $b64_sig),
    'verified RSA-SHA256 hash signature'
);
ok(
    !$verifier->_verify_signature($sig_alg, $mismatched_text, $b64_sig),
    'failed to verify mismatched RSA-SHA256 hash signature'
);

done_testing();
exit;


sub parse_xml_to_xc {
    my $xml_source = shift;

    my $parser = XML::LibXML->new();
    my $doc    = $parser->parse_string($xml_source);
    my $xc     = XML::LibXML::XPathContext->new($doc->documentElement);

    while(@_) {
        my $prefix = shift;
        my $uri    = shift;
        $xc->registerNs($prefix => $uri);
    }
    $xc->setContextNode($doc->documentElement);
    return $xc;
}
