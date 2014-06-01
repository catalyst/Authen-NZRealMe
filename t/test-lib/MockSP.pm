package MockSP;

use 5.010;
use strict;
use warnings;
use autodie;

use parent 'Authen::NZRealMe::ServiceProvider';

use AuthenNZRealMeTestHelper;

use MIME::Base64    qw(decode_base64);
use HTTP::Response  qw();


sub _https_post {
    my($self, $url, $headers, $soap_body) = @_;

    my($artifact) = $soap_body =~ m{
        <\w+:Artifact>
          ([^<]+)
        </\w+:Artifact>
    }x;

    my $bytes = decode_base64($artifact);
    my($type_code, $index, $source_id, $msg_handle) = unpack('nna20a20', $bytes);
    my $file_name = sprintf('%s-assertion-%d.xml',
        $self->type eq 'login' ? 'login' : 'identity',
        $msg_handle
    );
    my $path_name = test_data_file($file_name);
    my $content = do {
        local($/);
        open my $fh, '<', $path_name;
        <$fh>;
    };
    my $resp = HTTP::Response->new(200, 'OK', [], $content );
    return $resp;
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
