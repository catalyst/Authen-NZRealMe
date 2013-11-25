Authen::NZRealMe
================

This Perl [CPAN module][1] provides an API for integrating your application
with the New Zealand RealMe login and identity services (formerly "igovt
logon") using SAML 2.0 messaging.

The distribution also includes a command-line tool called nzrealme which can
be used for:

* generating certificate/key pairs for signing and SSL encryption
* creating/editing the Service Provider metadata file
* creating a bundle (zip file) containing metadata and certs for upload to the IdP
* generating AuthnRequest URLs
* decoding/dumping AuthnRequest URLs
* resolving SAMLart artifact responses and validating the response

 [1]: https://metacpan.org/release/Authen-NZRealMe

