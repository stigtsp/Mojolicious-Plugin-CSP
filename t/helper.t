use Mojo::Base -strict;

use Test::More;
use Mojolicious::Lite;
use Test::Mojo;

plugin 'Mojolicious::Plugin::CSP';

{
    get '/' => sub {
        my $self = shift;
        $self->csp("default-src 'self'");
        $self->render(text => 'Hello Mojo!');
    };

    my $t = Test::Mojo->new;
    $t->get_ok('/')->status_is(200)->header_is('Content-Security-Policy' => "default-src 'self';")->content_is('Hello Mojo!');
}

{
    get '/' => sub {
        my $self = shift;
        $self->csp("default-src 'self'; frame-src 'none'; object-src 'none'");
        $self->render(text => 'Hello Mojo!');
    };

    my $t = Test::Mojo->new;
    $t->get_ok('/')->status_is(200)->header_is('Content-Security-Policy' => "default-src 'self';")->content_is('Hello Mojo!');
}

done_testing();
