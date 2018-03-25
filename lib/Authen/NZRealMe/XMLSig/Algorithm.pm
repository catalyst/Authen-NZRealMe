package Authen::NZRealMe::XMLSig::Algorithm;

use strict;
use warnings;

=head1 ALGORITHM SIGNATURES

Authen::NZRealMe::XMLSig::Algorithm

This module provides support for encoding and decoding XML digital
signatures via various cryptographic algorithms.

=cut

use Carp          qw(croak);
use MIME::Base64  qw(encode_base64 decode_base64);

require Crypt::OpenSSL::RSA;

=head1 ALGORITHM METHODS

=head2 new( )

Base constructor for specific algorithm classes.  Should not be called
directly. Use one of the following instead:

  my $algorithm = Authen::NZRealMe->class_for('algorithm_sha256')->new();

  my $algorithm = Authen::NZRealMe->new_algorithm_from_SignatureMethod($signature_method);

  my $algorithm = Authen::NZRealMe->new_algorithm_from_DigestMethod($digest_method, $ref_uri);

=cut

sub new {
    my $class = shift;

    my $self = bless { @_ }, $class;

    return $self;
}


=head2 algorithm ()

Returns a short name of this encryption algorithm.

Subclass must provide this method.

=head2 encrypt (value)

Returns the encryption of C<value>.

Subclass must provide this method.

=head2 SignatureMethod ()

Returns the SignatureMethod URI of this encryption algorithm.

Subclass must provide this method.

=head2 DigestMethod ()

Returns the DigestMethod URI of this encryption algorithm.

Subclass must provide this method.

=cut

sub algorithm       { croak "subclass needs to provide algorithm method" }
sub encrypt         { croak "subclass needs to provide encrypt method" }
sub SignatureMethod { croak "subclass needs to provide SignatureMethod method" }
sub DigestMethod    { croak "subclass needs to provide DigestMethod method" }

=head2 xml_digest (xml)

Returns the encrypted C<xml> encoded in base64

=cut

sub xml_digest {
    my($self, $xml) = @_;

    my $digest = $self->encrypt($xml);

    return encode_base64($digest, '');
}

=head2 rsa_signature (private_key_text, plaintext, eol)

Returns the base64 encoded signature of C<plaintext> encrypted using
C<private_key_text> as the private key.

=cut

sub rsa_signature {
    my($self, $private_key_text, $plaintext, $eol) = @_;

    $eol //= "\n";

    my $rsa_key = Crypt::OpenSSL::RSA->new_private_key($private_key_text);

    $self->sign_options($rsa_key);

    my $bin_signature = $rsa_key->sign($plaintext);
    return encode_base64($bin_signature, $eol);
}

=head2 verify_rsa_signature (plaintext, signature, public_key_text)

Verifies whether the given C<signature> is valid for the plaintext
encoded with the C<public_key_text>.

=cut

sub verify_rsa_signature {
    my($self, $plaintext, $signature, $public_key_text) = @_;

    my $rsa_cert = Crypt::OpenSSL::RSA->new_public_key($public_key_text);

    $self->sign_options($rsa_cert);

    my $bin_sig = decode_base64($signature);

    return $rsa_cert->verify($plaintext, $bin_sig);
}

1;
