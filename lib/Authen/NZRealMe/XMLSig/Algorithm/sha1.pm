package Authen::NZRealMe::XMLSig::Algorithm::sha1;

use strict;
use warnings;

use Digest::SHA   qw(sha1);

our @ISA = Authen::NZRealMe->class_for('signer_algorithm');

use constant algorithm       => 'sha1';
use constant SignatureMethod => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
use constant DigestMethod    => 'http://www.w3.org/2000/09/xmldsig#sha1';

sub encrypt { shift; sha1(@_); }

sub sign_options {
    my ($self, $rsa) = @_;

    $rsa->use_pkcs1_padding();
    $rsa->use_sha1_hash();

    return $rsa;
}

1;
