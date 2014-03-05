requires 'perl', '5.010';
requires 'XML::Generator';
requires 'XML::LibXML';
requires 'URI';
requires 'LWP';
requires 'WWW::Curl';
requires 'Crypt::OpenSSL::RSA';
requires 'Crypt::OpenSSL::X509';
requires 'Digest::SHA';
requires 'IO::Compress::RawDeflate';
requires 'Data::UUID';

on 'test' => sub {
    requires 'Test::More', '0.88';
};

