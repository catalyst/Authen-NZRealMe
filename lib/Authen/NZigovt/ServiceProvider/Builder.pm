package Authen::NZigovt::ServiceProvider::Builder;

use warnings;
use strict;
use feature "switch";

use Term::ReadLine;

my $prog_name = 'nzigovt';
my $term      = undef;

my @fields = (

    id => <<EOF,
The metadata file is identified by a unique 'ID'.  This identifier is not
used for any purpose other than as a target for the digital signature.
You might want to use an ID of the form:

  AGENCY-SP-DEV
EOF

    entity_id => <<EOF,
The 'Entity ID' is a URL that identifies the igovt logon service privacy
domain that your service provider is a part of.  You must supply a value
here that has been registered with (or provided to you by) the igovt logon
service. The format for this value is:

  https://<sp-domain>/<privacy-realm>/<application-name>
EOF

    url_assertion_consumer => <<EOF,
After a login is complete, which URL on your site should the IdP redirect
the user back to?
EOF

    url_single_logout => <<EOF,
After a user has logged out, which URL on your site should the IdP redirect
the user back to?
EOF

    contact_company => <<EOF,
Which company name should be listed in the technical contact details?
EOF

    contact_first_name => <<EOF,
What is the first name of the technical contact person?
EOF

    contact_surname => <<EOF,
What is the first name of the technical contact person?
EOF

);

sub build {
    my($class, $sp) = @_;

    $class->_check_conf($sp->conf_dir);
    my %f = @fields;
    my $args =  { map { $_ => $sp->{$_} } keys %f };

    $term = Term::ReadLine->new($prog_name);
    $term->Attribs->ornaments(0);

    print <<EOF;
This tool will allow you to create or edit your Service Provider metadata
file by leading you through a series of questions and then prompting you
to save the results.

EOF

    _prompt_yes_no('Do you wish to continue with this process? (y/n) ', 'y')
        or return;

    TRY: while(1) {
        for(my $i = 0; $i <= $#fields; $i += 2) {
            my $key    = $fields[$i];
            my $prompt = $fields[$i + 1];

            print "\n$prompt\n";
            my $field_ok = 0;
            my $value = $args->{$key};
            do {
                $value = $term->readline("$key> ", $value);
                my $method = "_validate_$key";
                $field_ok = $class->can($method) ? $class->$method($value) : 1;
            } until $field_ok;
            $args->{$key} = $value;
        }

        last TRY if _prompt_yes_no('Do you wish to save the results? (y/n) ', '');
        redo TRY if _prompt_yes_no('Do you wish to try again? (y/n) ', '');
        exit 1;
    }

    return $args;
}


sub _validate_id {
    my($class, $value) = @_;

    given($value) {
        when(/\A[a-z_][\w-]*\z/i) { return 1; }
        when(/\A\z/i) {
            print "ID must not be blank\n";
        }
        when(/\A[^a-z_]/i) {
            print "ID should start with a letter\n";
        }
        default {
            print "ID should contain only letters, numbers, _ and - characters\n";
        }
    };
    return;
}


sub _validate_entity_id {
    my($class, $value) = @_;

    given($value) {
        when(m{\Ahttps://[\w.-]+/[\w.-]+/[\w.-]+\z}i) {
            return 1;
        }
        when(/\A\z/i) {
            print "Entity ID must not be blank\n";
        }
        default {
            print "Entity ID should match the URL pattern above\n";
        }
    };
    return;
}


sub _check_conf {
    my $class = shift;
    my $dir   = shift or die "conf_dir not defined\n";

    die "Config directory '$dir' does not exist\n" unless -d "$dir/.";

    my @missing = map {  -e "$dir/$_" ? () : "$dir/$_" } qw(
        sp-sign-crt.pem sp-sign-key.pem sp-ssl-crt.pem sp-ssl-key.pem
    );
    if(@missing) {
        die join("\n",
            "The following key-pair files are missing:",
            map { " * $_" } @missing,
        ) . "\nSee perldoc Authen::NZigovt for more details\n"
    }

    warn "WARNING: $dir/metadata-idp.xml does not exist\n"
        unless -e "$dir/metadata-idp.xml";
}


sub _prompt_yes_no {
    my($prompt, $default) = @_;

    while(1) {
        my $resp = $term->readline($prompt, $default);

        next unless defined $resp;
        return 1 if $resp =~ /^(y|yes)$/i;
        return 0 if $resp =~ /^(n|no)$/i;
    }
}


1;


__END__

=head1 NAME

Authen::NZigovt::ServiceProviderBuilder - interactively create/edit Service Provider metadata

=head1 DESCRIPTION

This class is used for creating and editing the Service Provider metadata file.

=head1 METHODS

=head2 build

Called by the C<< nzigovt make-meta >> command to create or edit the Service
Provider metadata file through a series of interactive questions and answers.

=head1 COPYRIGHT

Copyright 2010 Grant McLean E<lt>grant@catalyst.net.nzE<gt>

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut


