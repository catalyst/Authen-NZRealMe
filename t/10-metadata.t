#!perl

use Test::More;

use FindBin;
use File::Spec;
use lib File::Spec->catdir($FindBin::Bin, 'test-lib');

use AuthenNZigovtTestHelper;

require Authen::NZigovt;

ok(1, 'successfully loaded the Authen::NZigovt package');

my $conf_dir = test_conf_dir();

my $sp = Authen::NZigovt->service_provider( conf_dir => $conf_dir );

isa_ok($sp, 'Authen::NZigovt::ServiceProvider');

is($sp->conf_dir, $conf_dir, "SP's conf_dir looks good");
is($sp->id, 'EXAMPLE-SP-DEV', "SP ID loaded from metadata looks good");
is($sp->entity_id, 'https://www.example.govt.nz/app/sample',
    "SP EntityID loaded from metadata looks good");
is($sp->url_assertion_consumer, 'https://www.example.govt.nz/app/sample/saml-acs',
    "SP ACS URL from metadata looks good");
is($sp->url_single_logout, 'https://www.example.govt.nz/app/sample/saml-logout',
    "SP SingleLogout URL from metadata looks good");

my $idp = $sp->idp;

isa_ok($idp, 'Authen::NZigovt::IdentityProvider');
is($idp->entity_id, 'https://www.mts-logon.i.govt.nz/mts2',
    "IdP EntityID loaded from metadata looks good");

done_testing();


