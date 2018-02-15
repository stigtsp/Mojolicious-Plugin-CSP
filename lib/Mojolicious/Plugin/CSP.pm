package Mojolicious::Plugin::CSP;

use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';
use Hash::Merge; #merge
use Session::Token;

our $VERSION = '0.01-s';

sub register {
    my ( $self, $app, $conf ) = @_;

    my $csp;
    my $enable_nonce;

    if (not keys %{$conf}) {
        $conf = $self->_parse_csp("default-src 'none'");
    }

    my $config;
    if ($app->config->{csp}) {
        $config = $self->_parse_csp($app->config->{csp});
    }

    foreach my $parameter (keys %{$conf}) {
        if ($parameter eq 'default-src' && 
            exists $config->{$parameter}) {
                next;
        } else {
            $config->{$parameter} = $conf->{$parameter};
        }
    }

    # Routes
    if ($config->{enable_builtin_csp_report_parser}) {
        my $r = $app->routes;
        $r->route('/csp_report_parser')->to(cb => \&_csp_report_parser);
    }

    if ($config->{enable_nonce}) {
        $enable_nonce=1;
        delete $config->{enable_nonce};
    }


    if ( $config ) {
        $csp = $self->_flatten_csp($config);
    }

    $app->hook(before_dispatch => sub {
        my ($c) = @_;

        my $local_csp = $csp;

        if ($enable_nonce) {
            my $nonce = $c->stash->{csp_nonce} =  Session::Token->new->get();
            my %cfg = %{ $config };
            $cfg{"script-src"} .= " ".qq['nonce-$nonce'];            
            $local_csp = $self->_flatten_csp(\%cfg);
        }
        $c->res->headers->add('Content-Security-Policy' => $local_csp);

        return 1;
    });

    # Adding "csp" helper
    $app->helper(
        csp => sub {
            my ( $self, $csp ) = @_;

            if ($csp !~ m/;$/) {
                $csp .= ';';
            }

            $self->res->headers->remove('Content-Security-Policy');
            $self->res->headers->add('Content-Security-Policy' => $csp);

            return $csp;
        },
        csp_append => sub {
            my ( $self, $csp ) = @_;

            my $requested_csp = $self->_parse_csp($csp);
            my $existing_csp = $self->_parse_csp(
                $self->res->headers->header('Content-Security-Policy')
            );

            my $new_csp = merge($existing_csp, $requested_csp);

            if ($new_csp !~ m/;$/) {
                $new_csp .= ';';
            }

            $self->res->headers->remove('Content-Security-Policy');
            $self->res->headers->add('Content-Security-Policy' => $new_csp);

            return $new_csp;
        }
    );

    return $self;
}

sub _csp_report_parser {
    my $self = shift;

    return;
}

sub _parse_csp {
    my ($self, $csp) = @_;

    my $tmp_csp;
    my @policies = split /(;|,)/, $csp;

    if (scalar @policies == 0) {
        push @policies, $csp; 
    }

    foreach my $policy (@policies) {
        my ($policy_name, $policy_setting) = split /\s+/, $policy;

        $tmp_csp->{$policy_name} = $policy_setting;
    }

    return $tmp_csp;
}

sub _flatten_csp {
    my ($self, $csp) = @_;

    my $csp_string;
    foreach my $policy (sort keys %{$csp}) {
        $csp_string .= "$policy ".$csp->{$policy}.q[;];
    }

    return $csp_string;
}

1;

=pod

=over

=item * https://en.wikipedia.org/wiki/Content_Security_Policy

=back