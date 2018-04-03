package MockIdP;

use strict;
use warnings;

use parent 'Authen::NZRealMe::IdentityProvider';

use MIME::Base64 qw(encode_base64);
use Digest::SHA  qw(sha1);


use AuthenNZRealMeTestHelper;

sub make_artifact {
    my($self, $file_name, $target_id, $algorithm) = @_;

    my $type_code   = 4;
    my $index       = 0;
    my $source_id   = sha1( $self->entity_id );
    my $artifact = pack('n n a20 C/A* C/A* C/A*', $type_code, $index, $source_id, $file_name, $target_id, $algorithm);

    return encode_base64($artifact, '');
}

1;

