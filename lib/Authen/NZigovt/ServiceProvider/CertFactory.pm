package Authen::NZigovt::ServiceProvider::CertFactory;

use warnings;
use strict;
use feature "switch";

use Term::ReadLine;

my $prog_name = 'nzigovt';
my $term      = undef;


my @fields = (

    env => <<EOF,
Which environment do you wish to generate certficates for?  Please answer
either 'ITE' or 'PROD'.
EOF

    org => <<EOF,
Enter your organisation name (e.g.: "Department of Innovation" - without the
quotes).
EOF

    domain => <<EOF,

Enter the domain name for your agency.  You might choose to include an
application prefix (e.g.: facetube.innovation.govt.nz) if your applications
will have separate igovt integrations but just the domain name is usually
sufficient (e.g.: innovation.govt.nz).
EOF

);


sub generate_certs {
    my($class, $conf_dir, %args) = @_;

    if(not keys %args) {
        %args = $class->prompt_for_parameters() or exit 1;
    }
    check_args(\%args);
    $args{conf_dir} = $conf_dir;

    die "'$conf_dir' is not a directory\n" unless -d "$conf_dir/.";

    my $key_file = "$conf_dir/sp-sign-key.pem";
    generate_private_key($key_file);
    generate_certificate('sig', $key_file, \%args);

    $key_file = "$conf_dir/sp-ssl-key.pem";
    generate_private_key($key_file);
    generate_certificate('ssl', $key_file, \%args);

    if($args{env} eq 'prod') {
        print "\nSuccessfully generated two certificate signing requests.\n"
            . "Once you have the certificates signed, save them as\n"
            . "sp-sign-crt.pem and sp-ssl-crt.pem\n";
    }
    else {
        print "\nSuccessfully generated two self-signed certificates.\n";
    }
}


sub prompt_for_parameters {
    my($class) = @_;
    my $args   =  { };

    $term = Term::ReadLine->new($prog_name);
    if($term->Attribs and $term->Attribs->can('ornaments')) {
        $term->Attribs->ornaments(0);
    }
    else {
        warn "Consider installing Term::ReadLine::Gnu for better terminal handling.\n";
    }

    print <<EOF;
This tool will allow you to generate self-signed certificates for your ITE
integration or CSRs (Certificate Signing Requests) for your production
integration.  You will be asked a short list of questions.

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

        print "\nReady to generate certificates with the parameters:\n"
            . "  Environment:  $args->{env}\n"
            . "  Organisation: $args->{org}\n"
            . "  Domain:       $args->{domain}\n\n";

        last TRY if _prompt_yes_no('Do you wish to generate certificates now? (y/n) ', '');
        redo TRY if _prompt_yes_no('Do you wish to try again? (y/n) ', '');
        exit 1;
    }

    return %$args;
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


sub generate_private_key {
    my($key_path) = @_;

    system('openssl', 'genrsa', '-out', $key_path, '2048') == 0
        or exit 1;
}


sub generate_certificate {
    my($type, $key_path, $args) = @_;

    my($name, $out_base);
    if($type eq 'sig') {
        $name     = "$args->{env}.sa.saml.sig.$args->{domain}";
        $out_base = "sp-sign";
    }
    else {
        $name     = "$args->{env}.sa.mutual.ssl.$args->{domain}";
        $out_base = "sp-ssl";
    }

    my @command = (
        'openssl', 'req', '-new', '-key', $key_path,
        '-subj', "/CN=${name}/O=$args->{org}",
        '-days', '1095',
    );

    if($args->{env} eq 'prod') {
        push @command, '-out', "${out_base}.csr";
    }
    else {
        push @command, '-out', "${out_base}-crt.pem",
            '-x509', '-set_serial', gen_serial();
    }

    system(@command) == 0 or exit 1;
}


sub gen_serial {
    my @h = qw(0 1 2 3 4 5 6 7 8 9 a b c d e f);

    return '0x' . join '', @h[rand(8)], map { @h[rand(16)] } (1..15);
}


sub check_args {
    my($args) = @_;

    die "Need organisation name to generate certs\n" unless $args->{org};
    die "Need domain name to generate certs\n"       unless $args->{domain};

    $args->{domain} =~ s/^www[.]//;

    die "Need environment (MTS/ITE/PROD) to generate certs\n"
        unless $args->{env};

    $args->{env} = lc($args->{env});
    die "Environment must be 'MTS', 'ITE' or 'PROD'\n"
        unless $args->{env} =~ /^(mts|ite|prod)$/;

    warn
        "WARNING: It should not be necessary to generate certificates for MTS.\n"
      . "         You should just use the certificate and key files from the\n"
      . "         MTS integration pack.\n\n"
      . "         Proceeding with certificate generation as requested.\n\n"
        if $args->{env} eq 'mts';
}


sub _validate_env {
    my($class, $value) = @_;

    return 1 if $value =~ /^(ite|prod)$/i;

    print "Environment must be 'ITE' or 'Prod'\n";
    return;
}


sub _validate_org {
    my($class, $value) = @_;

    given($value) {
        when(m{\A[a-z0-9(),./ -]+\z}i) { return 1; }
        when(m{\A\z}i) {
            print "Organisation name must not be blank\n";
        }
        default {
            print "Organisation name should be plain text without special characters\n";
        }
    };
    return;
}



1;
