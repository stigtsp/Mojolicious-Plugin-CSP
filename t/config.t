use Mojo::Base -strict;

use Test::More;
use Mojolicious::Lite;
use Test::Mojo;

my $config = plugin 'Mojolicious::Plugin::Config' => {file => 'examples/config.t.conf'};
plugin 'Mojolicious::Plugin::CSP';

get '/' => sub {
  my $self = shift;
  $self->render(text => 'Hello Mojo!');
};

my $t = Test::Mojo->new;
$t->get_ok('/')->status_is(200)->header_is('Content-Security-Policy' => "default-src 'self';")->content_is('Hello Mojo!');

done_testing();
