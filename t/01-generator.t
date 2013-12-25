#!perl
use strict;
use warnings FATAL => 'all';
use Test::More;

use File::Temp 'tempdir';
use Cwd 'cwd';
use Mojolicious::Commands;

my $cwd = cwd;
my $tmp = tempdir CLEANUP => 1;

chdir $tmp;

# basic generator
require Mojolicious::Command::generate::bootstrap_app;
my $bootstrap_app = Mojolicious::Command::generate::bootstrap_app->new;
ok $bootstrap_app->description, 'generator has a description';
ok $bootstrap_app->usage, 'generator has a usage';

# run generator and app tests
ok $bootstrap_app->run('MyApp::Test'), 'generator runs';
ok -d 'my_app_test', 'created application directory';
ok -e 'my_app_test/script/migrate', 'created executable migration script';
ok -f 'my_app_test/public/bootstrap-3.0.3/css/bootstrap.min.css', 'created Bootstrap css';
ok -f 'my_app_test/public/bootstrap-3.0.3/css/bootstrap-theme.min.css', 'created Bootstrap theme css';
ok -f 'my_app_test/public/bootstrap-3.0.3/js/bootstrap.min.js', 'created Bootstrap js';
ok -f 'my_app_test/public/bootstrap-3.0.3/js/jquery-1.10.2.min.js', 'created jQuery';
ok -f 'my_app_test/public/bootstrap-3.0.3/fonts/glyphicons-halflings-regular.eot', 'created Bootstrap eot glyphicons';
ok -f 'my_app_test/public/bootstrap-3.0.3/fonts/glyphicons-halflings-regular.svg', 'created Bootstrap svg glyphicons';
ok -f 'my_app_test/public/bootstrap-3.0.3/fonts/glyphicons-halflings-regular.ttf', 'created Bootstrap ttf glyphicons';
ok -f 'my_app_test/public/bootstrap-3.0.3/fonts/glyphicons-halflings-regular.woff', 'created Bootstrap woff glyphicons';

SKIP: {
    skip 'Set APP_TESTING to check if the generated app works.', 1 unless ( $ENV{APP_TESTING} );
    chdir 'my_app_test',
    system 'script/migrate --init';
    system 'script/my_app_test test 2>&1 > /dev/null'; # redirecting to NULL because test parser could get confused finding something that is TAP too
    ok $? << 8 == 0, 'application tests passed';
}

chdir $cwd;

done_testing();
