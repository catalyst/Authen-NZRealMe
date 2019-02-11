package Authen::NZRealMe::XMLSig;

use strict;
use warnings;

=head1 NAME

Authen::NZRealMe::XMLSig - XML digital signature generation/verification

=head1 DESCRIPTION

This module implements the subset of http://www.w3.org/TR/xmldsig-core/
required to interface with the New Zealand RealMe Login service using SAML 2.0
messaging.

=cut


use Carp          qw(croak);
use Digest::SHA   qw(sha1 sha1_base64 sha256);
use MIME::Base64  qw(encode_base64 decode_base64);

use Authen::NZRealMe::CommonURIs qw(URI NS_PAIR);

require XML::LibXML;
require XML::LibXML::XPathContext;
require XML::Generator;
require Crypt::OpenSSL::RSA;
require Crypt::OpenSSL::X509;

my(%transforms_by_name, %transforms_by_uri);
__PACKAGE__->register_transform_method($_, URI($_)) foreach (qw(
    c14n
    c14n_wc
    c14n11
    c14n11_wc
    ec14n
    ec14n_wc
    sha1
    sha256
    env_sig
));

my(%sig_alg_by_name, %sig_alg_by_uri);
__PACKAGE__->register_signature_methods($_, URI($_)) foreach (qw(
    rsa_sha1
    rsa_sha256
));

use constant WITH_COMMENTS    => 1;
use constant WITHOUT_COMMENTS => 0;

sub new {
    my $class = shift;

    my $self = bless {
        id_attr   => 'ID',
        algorithm => 'algorithm_sha1',
        @_
    }, $class;

    my $algorithm = delete $self->{algorithm};
    $self->{_algorithm} = Authen::NZRealMe->class_for($algorithm)->new()
      or die "no algorithm class created";

    return $self;
}

sub id_attr    { shift->{id_attr};    }
sub _algorithm { shift->{_algorithm}; }

sub SignatureMethod { shift->_algorithm->SignatureMethod(); }
sub DigestMethod    { shift->_algorithm->DigestMethod(); }

sub rsa_signature {
    my $self = shift;

    return $self->_algorithm->rsa_signature($self->key_text, @_);
}

sub xml_digest {
    my $self = shift;

    return $self->_algorithm->xml_digest(@_);
}

sub sign {
    my($self, $xml, $target_id, %options) = @_;

    my $doc      = $self->_xml_to_dom($xml);
    $target_id   ||= $self->default_target_id($doc);
    my $id_attr  = $self->id_attr;
    my($target)  = $doc->findnodes("//*[\@${id_attr}='${target_id}']")
        or croak "Can't find element with ${id_attr}='${target_id}'";

    my $sig_info  = $self->_make_signed_info($target, $target_id);
    my $sig_value = $self->rsa_signature($self->_ec14n_xml($sig_info));

    my $sig_xml   = $self->_make_signature_xml($sig_info, $sig_value, %options);
    my $sig_frag  = $self->_xml_to_dom($sig_xml);

    if($target->hasChildNodes()) {
        $target->insertBefore($sig_frag, $target->firstChild);
    }
    else {
        $target->appendChild($sig_frag);
    }

    return $doc->toString;
}

sub sign_multiple_targets {
    my($self, $xml, $target_ids) = @_;
    my $doc = $self->_xml_to_dom($xml);

    die 'Passed in ref should be an array' if (ref $target_ids ne 'ARRAY');

    my $signature_method = $self->SignatureMethod();

    my $x = XML::Generator->new();

    # Generate the reference blocks for each target
    my $ns_ds   = [ NS_PAIR('ds') ];
    my $ns_wsse = [ NS_PAIR('wsse') ];
    my $signedinfo = $x->SignedInfo( $ns_ds,
        $x->CanonicalizationMethod( $ns_ds, { Algorithm => URI('ec14n') }),
        $x->SignatureMethod( $ns_ds, { Algorithm => $signature_method } ),
        $self->generate_reference_blocks($doc, $target_ids),
    ).'';

    # Generate SignatureValue for whole SignedInfo block
    my $canonical_signedinfo = $self->_canonicalize( URI('ec14n'), $signedinfo);
    my $signature = $self->rsa_signature($canonical_signedinfo, '');

    # Generate and add key info block
    my $x509 = Crypt::OpenSSL::X509->new_from_string($self->pub_cert_text);
    my $keyinfo_block = $x->KeyInfo( $ns_ds, { Id => 'KI-'.$self->_key_fingerprint($x509).'1' },
        $x->SecurityTokenReference( $ns_wsse, { Id => 'STR-'.$self->_key_fingerprint($x509).'2' },
            $x->KeyIdentifier( $ns_wsse, { EncodingType => URI('wss_b64'), ValueType => URI('wss_sha1') },
                $self->_hex_to_b64($x509->fingerprint_sha1()), # RealMe uses the raw fingerprint bytes b64encoded, rather than a plain fingerprint
            ),
        ),
    ).'';

    # Build combined xml block
    my $signature_block = $x->Signature( $ns_ds, { Id => 'SIG-4' },
        $signedinfo,
        $x->SignatureValue( $ns_ds, $signature ),
        $keyinfo_block,
    ).'';

    # Insert whole block as the last element in the soap:Header section
    my $sig_dom = $self->_xml_to_dom($signature_block);
    my $xc     = XML::LibXML::XPathContext->new( $doc );
    $xc->registerNs( NS_PAIR('soap12') );
    $xc->registerNs( NS_PAIR('wsse') );
    my ( $security_node ) = $xc->findnodes("/soap12:Envelope/soap12:Header/wsse:Security");
    $security_node->appendChild($sig_dom);
    return $doc->toString(0);
}

sub _key_fingerprint {
    my ($self, $x509) = @_;
    my $fingerprint = $x509->fingerprint_sha1();
    $fingerprint =~ s/://g;
    return $fingerprint;
}

sub _hex_to_b64 {
    shift;
    my $hex = shift;
    $hex =~ s/://g;
    my $bin = pack("H*", $hex);
    my $b64 = encode_base64($bin, '');
    return $b64;
}

sub generate_reference_blocks {
    my ($self, $doc, $target_ids) = @_;

    return unless @$target_ids;

    # Generate the reference blocks for each target, using sha256 encryption
    my $algorithm_sha256 = Authen::NZRealMe->class_for('algorithm_sha256')->new();

    my @signedinfo;
    foreach my $target ( @$target_ids ) {
        push @signedinfo, $self->_generate_reference_block($doc, $target, $algorithm_sha256);
    }

    return join '', @signedinfo;
}

sub _generate_reference_block {
    my ($self, $doc, $target, $algorithm) = @_;

    my $target_id = $target->{id};
    my $inclusive_namespaces = $target->{namespaces};

    my $c14n_frag = $self->_generate_ec14n_xml($doc, $target_id, $inclusive_namespaces);

    my $digest        = $algorithm->xml_digest($c14n_frag);
    my $digest_method = $algorithm->DigestMethod();

    my $x = XML::Generator->new();

    my $prefix_hash = {};
    $prefix_hash = { PrefixList => join( ' ', @$inclusive_namespaces) } if ($inclusive_namespaces);

    my $ns_ds    = [ NS_PAIR('ds') ];
    my $ns_ec14n = [ NS_PAIR('ec14n') ];
    my $block = $x->Reference( $ns_ds, { URI => "#$target_id" },
        $x->Transforms( $ns_ds,
            $x->Transform( $ns_ds, { Algorithm => URI('ec14n') },
                $x->InclusiveNamespaces( $ns_ec14n, $prefix_hash ),
            ),
        ),
        $x->DigestMethod( $ns_ds, { Algorithm => $digest_method } ),
        $x->DigestValue( $ns_ds, $digest ),
    ) . "\n";
    return $block;
}

sub _generate_ec14n_xml {
    my ($self, $doc, $target_id, $inclusive_namespaces) = @_;
    my $id_attr  = $self->id_attr;
    my $xc     = XML::LibXML::XPathContext->new( $doc );
    $xc->registerNs( NS_PAIR('wsu') );
    my($target)  = eval {
        $xc->findnodes("//*[\@${id_attr}='${target_id}']")
    } or croak "Can't find element with ${id_attr}='${target_id}'\n$@";

    return $self->_ec14n_xml($target, WITHOUT_COMMENTS, $inclusive_namespaces);
}


sub default_target_id {
    my($self, $doc) = @_;

    my $id_attr    = $self->id_attr;
    my($target_id) = map { $_->to_literal } $doc->findnodes("//*/\@${id_attr}")
        or croak "Can't find element with '${id_attr}' attribute";

    return $target_id;
}


sub _canonicalize {
    my($self, $c14n_method_uri, $xml, $inclusive_namespaces) = @_;

    my $uri_ec14n = URI('ec14n') =~ s/#$//r;
    my($base_uri, $hash_frag) =
        $c14n_method_uri =~ m{\A(http:[^#]+)(?:#(.*))\z}
            or die "Can't parse CanonicalizationMethod: $c14n_method_uri";
    my $comments = WITHOUT_COMMENTS;
    if($hash_frag && $hash_frag eq 'WithComments') {
        $comments = WITH_COMMENTS;
    }
    if($base_uri eq URI('c14n')) {
        return $self->_c14n_xml($xml, $comments);
    }
    elsif($base_uri eq $uri_ec14n) {
        return $self->_ec14n_xml($xml, $comments, $inclusive_namespaces);
    }
    die "Unsupported canonicalization method: $c14n_method_uri";
}


sub _c14n_xml {
    my($self, $frag, $comments) = @_;

    if(not ref $frag) {   # convert XML string to a DOM node
        $frag = $self->_xml_to_dom($frag);
    }

    return $frag->toStringC14N($comments);
}

sub _ec14n_xml {
    my($self, $frag, $comments, $inclusive_namespaces) = @_;

    $inclusive_namespaces //= [];

    if(not ref $frag) {   # convert XML string to a DOM node
        $frag = $self->_xml_to_dom($frag);
    }

    return $frag->toStringEC14N($comments,'',$inclusive_namespaces);
}


sub _xml_to_dom {
    my($self, $xml) = @_;

    my $parser = XML::LibXML->new();
    my $doc    = $parser->parse_string($xml);
    return $doc->documentElement;
}


sub _make_signed_info {
    my($self, $frag, $id) = @_;

    my($ds_pref, $ds_uri) = NS_PAIR('ds');
    my $c14n_frag  = $self->_ec14n_xml($frag);
    my $digest     = $self->xml_digest($c14n_frag);
    my $sig_info   = $self->_signed_info_xml($id, $digest);

    return $sig_info;
}


sub _make_signature_xml {
    my($self, $sig_info, $sig_value, %options) = @_;

    my($ds_pref, $ds_uri) = NS_PAIR('ds');

    my $x509_certificate = '';
    if ($options{include_x509} && ($self->{pub_cert_file} || $self->{pub_cert_text})) {
        my $pub_cert_text = $self->pub_cert_text or die "No Public Key certificate defined";
        $pub_cert_text =~ s/^-----.*\n//mg;

        $x509_certificate = qq{<$ds_pref:KeyInfo>
<$ds_pref:X509Data>
<$ds_pref:X509Certificate>
${pub_cert_text}</$ds_pref:X509Certificate>
</$ds_pref:X509Data>
</$ds_pref:KeyInfo>
};
    }

    return qq{<$ds_pref:Signature xmlns:$ds_pref="$ds_uri">
${sig_info}
  <$ds_pref:SignatureValue>
${sig_value}</$ds_pref:SignatureValue>
</$ds_pref:Signature>};
}

sub _signed_info_xml {
    my($self, $frag_id, $frag_digest) = @_;

    my($ds_pref, $ds_uri) = NS_PAIR('ds');
    my $ec14n_uri         = URI('ec14n');
    my $env_sig_uri       = URI('env_sig');
    my $signaturemethod   = $self->SignatureMethod();
    my $digestmethod      = $self->DigestMethod();

    return qq{  <$ds_pref:SignedInfo xmlns:$ds_pref="$ds_uri">
    <$ds_pref:CanonicalizationMethod Algorithm="$ec14n_uri" />
    <$ds_pref:SignatureMethod Algorithm="${signaturemethod}" />
    <$ds_pref:Reference URI="#$frag_id">
        <$ds_pref:Transforms>
            <$ds_pref:Transform Algorithm="$env_sig_uri" />
            <$ds_pref:Transform Algorithm="$ec14n_uri" />
        </$ds_pref:Transforms>
        <$ds_pref:DigestMethod Algorithm="${digestmethod}" />
        <$ds_pref:DigestValue>${frag_digest}</$ds_pref:DigestValue>
    </$ds_pref:Reference>
</$ds_pref:SignedInfo>};
}


sub verify {
    my($self, $xml) = @_;

    my $xc  = $self->_xcdom_from_xml($xml);
    my @signed_fragment_paths;

    eval {
        foreach my $sig_block ( $self->_find_signature_blocks($xc) ) {

            # Confirm that the signature is valid for the <SignedInfo> block
            my $input = [ $xc, $sig_block->{sig_info_node}];
            my $sig_info_plaintext = $self->_apply_transform($sig_block->{c14n}, $input);
            $self->_verify_signature(
                $sig_block->{signature_algorithm},
                $sig_info_plaintext,
                $sig_block->{signature_value}
            ) or die "SignedInfo block signature does not match\n";

            # Confirm the digest value for each reference
            my $references = $sig_block->{references};
            die "Signature block contains no references\n" unless @$references;
            foreach my $ref ( @$references ) {
                my $fragment = $ref->{xml_fragment};
                my $transforms = $ref->{transforms};
                foreach my $transform ( @$transforms ) {
                    $fragment = $self->_apply_transform($transform, $fragment);
                }
                my $digest = $self->_apply_transform($ref->{digest_method}, $fragment);
                if($digest ne $ref->{digest_value}) {
                    die "Digest of signed element '$ref->{ref_id}' "
                      . "differs from that given in reference block\n"
                      . "Expected:   '$ref->{digest_value}'\n"
                      . "Calculated: '$digest'\n ";
                }

                push @signed_fragment_paths, $ref->{xml_fragment_path};
            }
        }
        1;
    } or do {
        my $message = $@ =~ s/\n+\z//r;
        croak "Signature verification failed. $message";
    };

    croak "XML document contains no signatures" unless @signed_fragment_paths;

    return 1;
}


sub parse_inline_pub_key_text_cert {
    my($self, $xc, $sig) = @_;

    # extract public key provided in the XML, if present
    my $pub_key_text;
    if (my $cert_text = $xc->findvalue(q{./ds:KeyInfo/ds:X509Data/ds:X509Certificate}, $sig)) {
        # Strip whitespace and re-wrap base64 encoded data to 64 chars per line
        $cert_text =~ s{\s+}{}g;
        my @cert_parts = $cert_text =~ m{(\S{1,64})}g;
        $cert_text = join(
            "\n",
            '-----BEGIN CERTIFICATE-----',
            @cert_parts,
            '-----END CERTIFICATE-----',
        ) . "\n";
        my $x509 = Crypt::OpenSSL::X509->new_from_string($cert_text);
        $pub_key_text = $x509->pubkey();
    }

    return $pub_key_text;
}

sub _parse_signature {
    my($self, $xc, $sig, $inline_certificate_check) = @_;

    my($sig_info) = $xc->findnodes(q{./ds:SignedInfo}, $sig)
        or die "Can't verify a signature without a 'SignedInfo' element";

    my $c14n_method = $xc->findvalue(q{./ds:CanonicalizationMethod/@Algorithm}, $sig_info)
        or die "Can't find CanonicalizationMethod in " . $sig->toString;

    my $sig_val = $xc->findvalue(q{./ds:SignatureValue}, $sig)
        or die "Can't find SignatureValue in " . $sig->toString;

    my $c14n_prefix_list = $xc->findvalue( q{./ds:CanonicalizationMethod/ec14n:InclusiveNamespaces/@PrefixList}, $sig_info);
    my $c14n_namespaces = [split ' ', $c14n_prefix_list];

    my $signature_method = $xc->findvalue(q{./ds:SignatureMethod/@Algorithm}, $sig_info)
        or die "Can't find SignatureMethod in " . $sig->toString;

    my $signature_algorithm = Authen::NZRealMe->new_algorithm_from_SignatureMethod($signature_method);

    my $plaintext = $self->_canonicalize($c14n_method, $sig_info, $c14n_namespaces);

    my $verified;
    if ($inline_certificate_check eq 'never') {
        # Only use the stored certificate
        $verified = $signature_algorithm->verify_rsa_signature($plaintext, $sig_val, $self->pub_key_text);
    }
    elsif ($inline_certificate_check eq 'always') {
        if (my $inline_pub_key_text = $self->parse_inline_pub_key_text_cert($xc, $sig)) {
            $verified = $signature_algorithm->verify_rsa_signature($plaintext, $sig_val, $inline_pub_key_text);
        }
    }
    elsif ($inline_certificate_check eq 'fallback') {
        # check using inline certificate first, if any
        if (my $inline_pub_key_text = $self->parse_inline_pub_key_text_cert($xc, $sig)) {
            $verified = eval {
                $signature_algorithm->verify_rsa_signature($plaintext, $sig_val, $inline_pub_key_text);
            };
        }

        # check using stored certificate, if not already verified
        $verified //= $signature_algorithm->verify_rsa_signature($plaintext, $sig_val, $self->pub_key_text);
    }
    else {
        die "Unrecognised value for inline_certificate_check: $inline_certificate_check";
    }

    die "SignedInfo block signature does not match $signature_method" unless $verified;

    my $references = [];

    foreach my $ref ( $xc->findnodes(q{.//ds:Reference}, $sig) ) {
        my $ref_data = {};

        my $ref_uri = $xc->findvalue('./@URI', $ref)
            or die "Reference element is missing the URI attribute";
        $ref_uri =~ s{^#}{};
        $ref_data->{ref_id} = $ref_uri;

        my ($digest_method) = map { $_->to_literal } $xc->findnodes(
            './ds:DigestMethod/@Algorithm',
            $ref
        ) or die "Unable to determine Signature Reference DigestMethod for $ref_uri";
        $ref_data->{digest_algorithm} = Authen::NZRealMe->new_algorithm_from_DigestMethod($digest_method, $ref_uri);

        my($digest) = map { $_->to_literal } $xc->findnodes(
            './ds:DigestValue',
            $ref
        ) or die "Unable to determine Signature DigestValue";
        $ref_data->{digest} = $digest;

        foreach my $xform (
            map { $_->to_literal } $xc->findnodes(
                q{./ds:Transforms/ds:Transform/@Algorithm},
                $ref
            )
        ) {
            next if $xform eq URI('env_sig');
            my $uri_c14n  = URI('c14n');
            my $uri_ec14n = URI('ec14n');
            next if $xform =~ m{\A\Q$uri_c14n\E(?:#WithComments)?\z};
            if ( $xform =~ m{\A\Q$uri_ec14n\E(?:WithComments)?\z} ) {
                my $inc_namespaces = $xc->findvalue(
                    q{./ds:Transforms/ds:Transform/ec14n:InclusiveNamespaces/@PrefixList},
                    $ref
                );
                $ref_data->{inclusive_namespaces} = [split ' ', $inc_namespaces] if $inc_namespaces;
                next;
            }
            die "Unsupported transformation: '$xform' on digest for $ref_uri";
        }
        push @$references, $ref_data;
    }

    return $references;
}


sub _find_signature_blocks {
    my($self, $xc) = @_;

    my @sig_blocks;
    foreach my $sig ( $xc->findnodes(q{//ds:Signature}) ) {
        push @sig_blocks, $self->_parse_signature_block($xc, $sig);
    }

    return @sig_blocks;
}


sub _parse_signature_block {
    my($self, $xc, $sig) = @_;

    my $sig_as_text = $sig->toString;
    my $block = {};

    my($sig_info) = $xc->findnodes(q{./ds:SignedInfo}, $sig)
        or die "Can't verify a signature without a 'SignedInfo' element";
    $block->{sig_info_node} = $sig_info;

    my($c14n_node) = $xc->findnodes(q{./ds:CanonicalizationMethod}, $sig_info)
        or die "Can't find CanonicalizationMethod in: '$sig_as_text'";
    my $c14n_method = $c14n_node->{Algorithm}
        or die "CanonicalizationMethod element lacks Algorithm attribute in: '$sig_as_text'";
    $block->{c14n} = $self->_find_transform($c14n_method);

    my($sigm_node) = $xc->findnodes(q{./ds:SignatureMethod}, $sig_info)
        or die "Can't find SignatureMethod in: '$sig_as_text'";
    my $sig_alg = $sigm_node->{Algorithm}
        or die "SignatureMethod element lacks Algorithm attribute in: '$sig_as_text'";
    $block->{signature_algorithm} = $self->_find_sig_alg($sig_alg);

    $block->{references} = [
        map { $self->_parse_signature_reference($xc, $_); }
            $xc->findnodes(q{.//ds:Reference})
    ];

    my($sig_value) = $xc->findvalue(q{./ds:SignatureValue}, $sig)
        or die "Can't find SignatureValue in: '$sig_as_text'";
    $sig_value =~ s/\s+//g;
    $block->{signature_value} = $sig_value;

    return $block;
}


sub _parse_signature_reference {
    my($self, $xc, $ref_node) = @_;

    my $ref_as_text = $ref_node->toString;
    my $ref_data = {};

    my $ref_uri = $xc->findvalue('./@URI', $ref_node)
        or die "Reference element is missing the URI attribute";
    $ref_uri =~ s{^#}{};
    $ref_data->{ref_id} = $ref_uri;

    my $target_node = $self->_find_element_by_uri_reference($xc, $ref_uri);
    $ref_data->{xml_fragment} = $self->_snapshot_node($xc, $target_node);
    $ref_data->{xml_fragment_path} = $self->_node_to_clarkian_path($target_node);

    $ref_data->{transforms} = [
        map {
            my $trans_node = $_;
            my $trans_as_text = $trans_node->toString;
            my $algorithm = $trans_node->{Algorithm}
                or die "Transform element lacks Algorithm attribute in: '$trans_as_text'";
            $self->_find_transform($algorithm);
        } $xc->findnodes(q{./ds:Transforms/ds:Transform}, $ref_node)
    ];

    my($digest_node) = $xc->findnodes(q{./ds:DigestMethod}, $ref_node)
        or die "Can't find DigestMethod in: '$ref_as_text'";
    my $digest_method = $digest_node->{Algorithm}
        or die "DigestMethod element lacks Algorithm attribute in: '$ref_as_text'";
    $ref_data->{digest_method} = $self->_find_transform($digest_method);

    my($digest) = map { $_->to_literal } $xc->findnodes('./ds:DigestValue', $ref_node);
    $ref_data->{digest_value} = $digest if $digest;

    return $ref_data;
}


sub _find_element_by_uri_reference {
    my($self, $xc, $ref_uri) = @_;
    my $id_attr  = $self->id_attr;
    my($target)  = $xc->findnodes("//*[\@${id_attr}='${ref_uri}']")
        or croak "Can't find element with ${id_attr}='${ref_uri}'";
    return $target;
}


sub _node_to_clarkian_path {
    my($self, $node) = @_;

    my $node_path = $node->nodePath();
    my %frag_ns;
    do {
        if(my $prefix = $node->prefix) {
            $frag_ns{$prefix} = $node->namespaceURI;
        }
        $node = $node->parentNode();
    } while($node);
    $node_path =~ s{([\w-]+):}{
        my $prefix = $1;
        my $uri = $frag_ns{$prefix};
        "{$uri}";
    }ge;
    return $node_path;
}


sub _snapshot_node {
    my($self, $xc, $node) = @_;

    # Clone node by serialising to string (leaving original intact), then
    # do envelope transform to discard <Signature> element and serialise
    # the resulting DOM fragment back to a string.

    my $tr_ec14n   = $self->_find_transform('ec14n_wc');
    my $tr_env_sig = $self->_find_transform('env_sig');
    my $fragment   = $self->_apply_transform($tr_ec14n, [ $xc, $node ]);
    $fragment = $self->_apply_transform($tr_env_sig, $fragment);
    return $self->_apply_transform($tr_ec14n, $fragment);
}


sub key_text {
    my($self) = @_;

    return $self->{key_text} if $self->{key_text};

    my $path = $self->{key_file}
        or croak "signing key must be set with 'key_file' or 'key_text'";

    $self->{key_text} = $self->_slurp_file($path);

    return $self->{key_text};
}


sub pub_key_text {
    my($self) = @_;

    return $self->{pub_key_text} if $self->{pub_key_text};

    my $cert_text = $self->pub_cert_text();
    my $x509 = Crypt::OpenSSL::X509->new_from_string($cert_text);
    $self->{pub_key_text} = $x509->pubkey();

    return $self->{pub_key_text};
}


sub pub_cert_text {
    my($self) = @_;

    return $self->{pub_cert_text} if $self->{pub_cert_text};
    my $path = $self->{pub_cert_file}
        or croak "signing cert must be set with 'pub_cert_file' or 'pub_cert_text'";

    $self->{pub_cert_text} = $self->_slurp_file($path);

    return $self->{pub_cert_text};
}


sub _slurp_file {
    my($self, $path) = @_;

    local($/) = undef;
    open my $fh, '<', $path or die "open($path): $!";
    my $text = <$fh>;

    return $text;
}


##############################################################################
# Methods for applying transforms
#
# A transform method takes a parameter '$input' which must either be a DOM
# fragment or a string.  Some of the transform methods also accept a second
# parameter '$args' which is a hashref defining the parameters of the transform
# in more detail.
#
# In the case of a DOM fragment, we also need the XPathContext object to
# facilitate the use of namespaces in queries.  Therefore the input parameter
# will be a reference to an array of two elements: the context object, followed
# by the DOM fragment node:
#
#     [ $xc, $node ]
#
# String input will be a simple scalar.  The _input_as_context_dom() helper
# method can be used to turn a string into a DOM fragment/context pair.
#
# The return value from the transform method will either be a DOM fragment
# /context pair or a string - depending on the type of transform.
#
# The process for calling these methods is:
#
# 1. Use $self->_find_transform($name_or_uri) to get a $transform hashref
#    describing the transform.
# 2. Optionally plug some extra parameters into the $transform hashref.
# 3. Call $self->_apply_transform($transform, $input)
#


sub register_transform_method {
    my($class, $name, $uri) = @_;
    my $transform = {
        name    => $name,
        uri     => $uri,
        method  => '_apply_transform_' . $name,
    };
    $transforms_by_name{$name} = $transform;
    $transforms_by_uri{$uri}   = $transform;
}


sub _find_transform {
    my($self, $identifier) = @_;

    my $transform = $transforms_by_name{$identifier}
        // $transforms_by_uri{$identifier}
           or die "Unknown transform: '$identifier'";
    return { %$transform };
}


sub _apply_transform {
    my($self, $transform, $input) = @_;

    my $method = $transform->{method} or die "transform does not include method";
    die "Unimplemented transformation method: '$method'" unless $self->can($method);
    return $self->$method($input, $transform);
}


sub _xcdom_from_xml {
    my($self, $xml) = @_;

    my $parser = XML::LibXML->new();
    my $doc    = $parser->parse_string($xml);
    my $xc     = XML::LibXML::XPathContext->new($doc->documentElement);

    $xc->registerNs( NS_PAIR('ds') );
    $xc->registerNs( NS_PAIR('soap12') );

    return $xc;
}


sub _input_as_context_dom {
    my($self, $xml) = @_;
    my $xc = $self->_xcdom_from_xml($xml);
    return [ $xc, $xc->getContextNode ];
}


sub _apply_transform_env_sig {
    my($self, $input, $args) = @_;

    $input = $self->_input_as_context_dom($input) unless ref $input;
    my($xc, $node) = @$input;
    my $ns_uri = $xc->lookupNs('ds');
    if(!$ns_uri or $ns_uri ne URI('ds')) {
        die "Expected XPathContext to map ds => " . URI('ds');
    }
    foreach my $sig ( $xc->findnodes(q{.//ds:Signature}, $node) ) {
        $sig->parentNode->removeChild($sig);
    }
    return [ $xc, $node ];
}


sub _apply_transform_c14n {
    my($self, $input, $args) = @_;
    return $self->_canonicalisation_transform('toStringC14N', WITHOUT_COMMENTS, $input, $args);
}


sub _apply_transform_c14n_wc {
    my($self, $input, $args) = @_;
    return $self->_canonicalisation_transform('toStringC14N', WITH_COMMENTS, $input, $args);
}


sub _apply_transform_c14n11 {
    my($self, $input, $args) = @_;
    return $self->_canonicalisation_transform('toStringC14N_v1_1', WITHOUT_COMMENTS, $input, $args);
}


sub _apply_transform_c14n11_wc {
    my($self, $input, $args) = @_;
    return $self->_canonicalisation_transform('toStringC14N_v1_1', WITH_COMMENTS, $input, $args);
}


sub _apply_transform_ec14n {
    my($self, $input, $args) = @_;
    return $self->_canonicalisation_transform('toStringEC14N', WITHOUT_COMMENTS, $input, $args);
}


sub _apply_transform_ec14n_wc {
    my($self, $input, $args) = @_;
    return $self->_canonicalisation_transform('toStringEC14N', WITH_COMMENTS, $input, $args);
}


sub _canonicalisation_transform {
    my($self, $c14n_method, $want_comments, $input, $args) = @_;
    $input = $self->_input_as_context_dom($input) unless ref $input;
    my($xc, $node) = @$input;
    my $xpath = ($args || {})->{xpath} // '';
    return $node->$c14n_method($want_comments, $xpath, $xc);
}


sub _apply_transform_sha1 {
    my($self, $input) = @_;
    if(ref($input)) {
        die "The SHA1 digest transform must be passed a string as input"
    }
    my $bin_digest = sha1($input);
    return encode_base64($bin_digest, '');
}


sub _apply_transform_sha256 {
    my($self, $input) = @_;
    if(ref($input)) {
        die "The SHA256 digest transform must be passed a string as input"
    }
    my $bin_digest = sha256($input);
    return encode_base64($bin_digest, '');
}


##############################################################################
# Methods for creating and verifying signatures using specific algorithms.
#
# Signatures are expected to be base64 encoded when provided as input or
# returned as output.
#


sub register_signature_methods {
    my($class, $name, $uri) = @_;
    my $signature_algorithm = {
        name          => $name,
        uri           => $uri,
        sign_method   => '_create_signature_' . $name,
        verify_method => '_verify_signature_' . $name,
    };
    $sig_alg_by_name{$name} = $signature_algorithm;
    $sig_alg_by_uri{$uri}   = $signature_algorithm;
}


sub _find_sig_alg {
    my($self, $identifier) = @_;

    my $sig_alg = $sig_alg_by_name{$identifier} // $sig_alg_by_uri{$identifier}
       or die "Unknown signature algorithm: '$identifier'";
    return $sig_alg;
}


sub _verify_signature {
    my($self, $sig_alg, $plaintext, $signature) = @_;
    my $method = $sig_alg->{verify_method}
        or die "transform does not include method";
    die "Unimplemented signature verification method: '$method'"
        unless $self->can($method);
    my $bin_sig = decode_base64($signature);
    return $self->$method($plaintext, $bin_sig);
}


sub _create_signature {
    my($self, $sig_alg, $plaintext) = @_;
    my $method = $sig_alg->{sign_method}
        or die "transform does not include method";
    die "Unimplemented signature creation method: '$method'"
        unless $self->can($method);
    my $bin_sig = $self->$method($plaintext);
    return encode_base64($bin_sig);
}


sub _verify_signature_rsa_sha1 {
    my($self, $plaintext, $bin_sig) = @_;
    my $rsa_pub_key = Crypt::OpenSSL::RSA->new_public_key($self->pub_key_text);
    $rsa_pub_key->use_pkcs1_padding();
    $rsa_pub_key->use_sha1_hash();
    return $rsa_pub_key->verify($plaintext, $bin_sig);
}


sub _verify_signature_rsa_sha256 {
    my($self, $plaintext, $bin_sig) = @_;
    my $rsa_pub_key = Crypt::OpenSSL::RSA->new_public_key($self->pub_key_text);
    $rsa_pub_key->use_pkcs1_oaep_padding();
    $rsa_pub_key->use_sha256_hash();
    return $rsa_pub_key->verify($plaintext, $bin_sig);
}


sub _create_signature_rsa_sha1 {
    my($self, $plaintext) = @_;
    my $rsa_key = Crypt::OpenSSL::RSA->new_private_key($self->key_text);
    $rsa_key->use_pkcs1_padding();
    $rsa_key->use_sha1_hash();
    return $rsa_key->sign($plaintext);
}


sub _create_signature_rsa_sha256 {
    my($self, $plaintext) = @_;
    my $rsa_key = Crypt::OpenSSL::RSA->new_private_key($self->key_text);
    $rsa_key->use_pkcs1_oaep_padding();
    $rsa_key->use_sha256_hash();
    return $rsa_key->sign($plaintext);
}


1;

=head1 SYNOPSIS

  my $signer = Authen::NZRealMe->class_for('xml_signer')->new(
      key_file => $path_to_private_key_file,
  );

  my $signed_xml = $signer->sign($xml, $target_id);

  my $verifier = Authen::NZRealMe->class_for('xml_signer')->new(
      pub_cert_text => $self->signing_cert_pem_data(),
  );

  $verifier->verify($xml, inline_certificate_check => '...');

=head1 METHODS

=head2 new( )

Constructor.  Should not be called directly.  Instead, call:

  Authen::NZRealMe->class_for('xml_signer')->new( options );

Options are passed in as key => value pairs.

When creating digital signatures, a private key must be passed to the
constructor using either the C<key_text> or the C<key_file> option.

When verifying digital signatures, a public key is required.  This may be
passed in using the C<pub_key_text> option or it will be extracted from the
X509 certificate provided in the C<pub_cert_text> or the C<pub_cert_file>
option.

=head2 id_attr( )

Returns the name of the attribute used to identify the element being signed.
Defaults to 'ID'.  Can be set by passing an C<id_attr> option to the
constructor.

=head2 sign( $xml, $target_id )

Takes an XML document and an optional element ID value and returns a string of
XML with a digital signature added.  The XML document can be provided either as
a string or as an XML::LibXML DOM object.

=head2 sign_multiple_targets ( $xml, $target_ids )

Takes an XML document and an array of hashes representing the ID and
InclusiveNamespaces of any DOM elements to sign, identified by an ID attribute
value. The input array should resemble this example:

        [ {
            id          => 's23a05470f2ac691e7ebc19a90b8f04a6336dad2fe',
            namespaces  => ['soap12'],
        },  {
            id          => 's254212e7245af1ee3a909a364273b0be7726e8808',
        } ]

The name of the attribute is determined by the id_attr method above.
The document will have a signature block generated and inserted into it, and
the method will return a string of the document and it's included signatures.

=head2 default_target_id( )

When signing a document, if no target ID is provided, this method is used to
find the first element with an 'ID' attribute.

=head2 rsa_signature( $plaintext, $eol )

Takes a plaintext string, calculates an RSA signature using the private key
passed to the constructor and returns a base64-encoded string. The C<$eol>
parameter can be used to specify the line-ending character used in the base64
encoding process (default: \n).

=head2 verify( $xml, inline_certificate_check => 'fallback' | 'always' | 'never' )

Takes an XML string (or DOM object); searches for signature elements;
 verifies the provided signature and message digest for each; and
 returns true on success.

The C<inline_certificate_check> option determines whether a
certificate in the XML and/or a stored certificate is used in the
signature verification.

If the provided document does not contain any signatures, or if an invalid
signature is found, an exception will be thrown.

=head2 key_text( )

Returns the private key text which will be used to initialise the
L<Crypt::OpenSSL::RSA> object used for generating signatures.

=head2 pub_key_text( )

Returns the public key text used to initialise the L<Crypt::OpenSSL::RSA>
object used for verifing signatures.

=head2 pub_cert_text( )

If the public key is being extracted from an X509 certificate, this method is
used to retrieve the text which defines the certificate.

=head2 register_transform_method( $name, $uri )

Used internally to register methods for implementing transformation algorithms
so that they can be looked by by URI.  May be called by a subclass to add
support for additional algorithms.

=head2 register_signature_methods( $name, $uri )

Used internally to register methods for implementing creation and verification
of signatures using specific algorithms so that they can be looked by by URI.
May be called by a subclass to add support for additional algorithms.

=head1 TODO

Documentation for:

=head2 DigestMethod()

=head2 SignatureMethod()

=head2 generate_reference_blocks()

=head2 parse_inline_pub_key_text_cert()

=head2 xml_digest()

=head1 SUPPORTED ALGORITHMS

=head3 sha1

=head3 sha256

=head1 SEE ALSO

See L<Authen::NZRealMe> for documentation index.


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2010-2019 Enrolment Services, New Zealand Electoral Commission

Written by Grant McLean E<lt>grant@catalyst.net.nzE<gt>

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

