package Authen::NZRealMe::XMLSig::Algorithm::sha256;

use strict;
use warnings;

use Digest::SHA   qw(sha256);

our @ISA = Authen::NZRealMe->class_for('signer_algorithm');

use constant algorithm       => 'sha256';
use constant SignatureMethod => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
use constant DigestMethod    => 'http://www.w3.org/2001/04/xmlenc#sha256';

sub encrypt { shift; sha256(@_); }

sub sign_options {
    my ($self, $rsa) = @_;

    $rsa->use_pkcs1_oaep_padding();
    $rsa->use_sha256_hash();

    return $rsa;
}

1;
