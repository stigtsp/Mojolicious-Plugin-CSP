use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
    dist_author          => 'jonasbn',
    dist_abstract        => 'Mojolicious plugin for controlling CSP headers', 
    module_name          => 'Mojolicious::Plugin::CSP', 
    license              => 'artistic_2', 
    recursive_test_files => 0, 
    create_readme        => 0, 
    create_makefile_pl   => 'traditional', 
    configure_requires   => {},
    build_requires       => {},
    requires             => {
        'Mojolicious::Plugin' => '0',
        'Hash::Merge'         => '0',
    },
);
$build->create_build_script();