#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'Authen::NZigovt' ) || print "Bail out!
";
}

diag( "Testing Authen::NZigovt $Authen::NZigovt::VERSION, Perl $], $^X" );

foreach my $key qw(
    service_provider
    identity_provider
    sp_builder
    resolution_request
    authen_request
    logon_strength
) {
    Authen::NZigovt->class_for($key);
}

ok(1, 'successfully loaded all support modules');
