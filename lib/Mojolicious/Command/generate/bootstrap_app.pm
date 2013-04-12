package Mojolicious::Command::generate::bootstrap_app;

use strict;
use warnings;
use Mojo::Base 'Mojolicious::Command';
use Mojo::Util qw(class_to_path class_to_file);
use String::Random qw(random_string);
use MIME::Base64;

our $VERSION = 0.02;

has description => "Generate Mojolicious application directory structure.\n";
has usage       => "usage: $0 generate bootstrap_app [NAME]\n";

sub render_base64_data {
    my ($self, $name) = (shift, shift);
    decode_base64(
        Mojo::Template->new->name("template $name from DATA section")
            ->render(Mojo::Loader->new->data(ref $self, $name), @_)
    );
}

sub render_base64_to_file {
    my ($self, $data, $path) = (shift, shift, shift);
    return $self->write_file($path, $self->render_base64_data($data, @_));
}

sub render_base64_to_rel_file {
    my $self = shift;
    $self->render_base64_to_file(shift, $self->rel_dir(shift), @_);
}

sub run {
    my ($self, $class) = @_;

    if (not $class =~ /^[A-Z](?:\w|::)+$/){
        die 'Your application name has to be a well formed (camel case) Perl module name like MyApp::Bootstrap.';
    }

    # get paths to create in ./lib
    my $model_namespace      = "${class}::DB";
    my $controller_namespace = "${class}::Controller";

    # get app lib path from class name
    my $name = class_to_file $class;
    my $app  = class_to_path $class;

    # script
    $self->render_to_rel_file('script', "$name/script/$name", $class);
    $self->chmod_file("$name/script/$name", 0744);

    # templates, static and assets
    $self->render_base64_to_rel_file('icons', "$name/public/bootstrap/img/glyphicons-halflings.png");
    $self->render_base64_to_rel_file('icons_white', "$name/public/bootstrap/img/glyphicons-halflings-white.png");
    $self->render_base64_to_rel_file('bootstrap_min_js', "$name/public/bootstrap/js/bootstrap.min.js");
    $self->render_base64_to_rel_file('bootstrap_min_css', "$name/public/bootstrap/css/bootstrap.min.css");
    $self->render_base64_to_rel_file('bootstrap_resp_min_css', "$name/public/bootstrap/css/bootstrap-responsive.min.css");

    $self->render_to_rel_file('static', "$name/public/index.html");
    $self->render_to_rel_file('style', "$name/public/style.css");

    $self->render_to_rel_file('layout', "$name/templates/layouts/bootstrap.html.ep");
    $self->render_to_rel_file('topnav', "$name/templates/elements/topnav.html.ep");
    $self->render_to_rel_file('footer', "$name/templates/elements/footer.html.ep");
    $self->render_to_rel_file('flash', "$name/templates/elements/flash.html.ep");

    $self->render_to_rel_file('login_form', "$name/templates/auth/login.html.ep");
    $self->render_to_rel_file('user_list_template', "$name/templates/users/list.html.ep");
    $self->render_to_rel_file('user_add_template', "$name/templates/users/add.html.ep");
    $self->render_to_rel_file('user_edit_template', "$name/templates/users/edit.html.ep");

    $self->render_to_rel_file('welcome_template', "$name/templates/example/welcome.html.ep");

    # application class
    my $model_name = class_to_file $model_namespace;
    $self->render_to_rel_file('appclass', "$name/lib/$app", $class, $controller_namespace, $model_namespace, $model_name, random_string('s' x 64));

    # controllers
    my $example_controller = class_to_path "${controller_namespace}::Example";
    my $auth_controller    = class_to_path "${controller_namespace}::Auth";
    my $users_controller   = class_to_path "${controller_namespace}::Users";
    $self->render_to_rel_file('example_controller', "$name/lib/$example_controller", "${controller_namespace}::Example");
    $self->render_to_rel_file('auth_controller', "$name/lib/$auth_controller", "${controller_namespace}::Auth");
    $self->render_to_rel_file('users_controller', "$name/lib/$users_controller", "${controller_namespace}::Users");

    # models
    my $schema = class_to_path $model_namespace;
    $self->render_to_rel_file('schema', "$name/lib/$schema", $model_namespace);
    my $usermodel = class_to_path "${model_namespace}::Result::User";
    $self->render_to_rel_file('users_model', "$name/lib/$usermodel", $model_namespace);

    # db_deploy_script
    $self->render_to_rel_file('migrate', "$name/script/migrate", $model_namespace, $model_name);
    $self->chmod_file("$name/script/migrate", 0744);
    $self->render_to_rel_file('fixture', "$name/share/fixtures/1/all_tables/users/1.fix");
    $self->render_to_rel_file('fixture_config', "$name/share/fixtures/1/conf/all_tables.json");

    # tests
    $self->render_to_rel_file('test', "$name/t/basic.t", $class );

    # config
    $self->render_to_rel_file('config', "$name/config.yml", $model_name);

    # share (to play with DBIx::Class::Migration nicely
    $self->create_rel_dir("$name/share");

    return 1;
}

1;

__DATA__

@@ script
% my $class = shift;
#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

# Start command line interface for application
require Mojolicious::Commands;
Mojolicious::Commands->start_app('<%= $class %>');

@@ schema
% my $class = shift;
use utf8;
package <%= $class %>;

use strict;
use warnings;

our $VERSION = 1;

use base 'DBIx::Class::Schema';

__PACKAGE__->load_namespaces;

1;

@@ appclass
% my $class                = shift;
% my $controller_namespace = shift;
% my $model_namespace      = shift;
% my $model_name           = shift;
% my $secret               = shift;
package <%= $class %>;
use Mojo::Base 'Mojolicious';
use YAML;
use DBIx::Connector;
use <%= $model_namespace %>;

# This method will run once at server start
sub startup {
    my $self = shift;

    # default config
    my %config = (
        database => {
            driver => 'SQLite',
            dbname => 'share/<%= $model_name %>.db',
            dbuser => '',
            dbpass => '',
            dbhost => '',
            dbport => 0,
        },
        session_secret => '<%= $secret %>',
        loglevel => 'info',
        hypnotoad => {
            listen => ['http://*:8080'],
        },
    );

    # load yaml file
    my $config_file = 'config.yml';
    my $config = YAML::LoadFile($config_file);

    # merge default value with loaded config
    @config{ keys %$config } = values %$config;

    # set application config
    $self->config(\%config);
    # set sectret
    $self->secret($self->config->{session_secret});
    # set loglevel
    $self->app->log->level($self->config->{loglevel});

    # Documentation browser under "/perldoc"
    $self->plugin('PODRenderer');

    # database connection prefork save with DBIx::Connector
    my $connector = DBIx::Connector->new(build_dsn($self->config->{database}));
    $self->helper(
        model => sub {
            my ($self, $resultset) = @_;
            my $dbh = <%= $model_namespace %>->connect( sub { return $connector->dbh } );
            return $resultset ? $dbh->resultset($resultset) : $dbh;
        }
    );

    # conditions
    my $conditions = {
        authenticated => sub {
            my $self = shift;

            unless ( $self->session('authenticated') ) {
                $self->flash( class => 'alert alert-info', message => 'Please log in first!' );
                $self->redirect_to('/login');
                return;
            }

            return 1;
        },
        admin => sub {
            my $self = shift;

            unless ( defined $self->session('user') && $self->session('user')->{admin} ) {
                $self->flash( class => 'alert alert-error', message => "You are no administrator" );
                $self->redirect_to('/');
                return;
            }

            return 1;
        }
    };

    # Router
    my $r       = $self->routes;
    my $admin_r = $r->under( $conditions->{admin} );
    my $auth_r  = $r->under( $conditions->{authenticated} );
    $r->namespaces(["<%= $controller_namespace %>"]);

    # Normal route to controller
    $r->get('/login')                  ->to('auth#login');
    $r->post('/authenticate')          ->to('auth#authenticate');

    $auth_r->get('/')                  ->to('example#welcome');
    $auth_r->get('/logout')            ->to('auth#logout');

    $auth_r->get('/users/edit/:id')    ->to('users#edit');
    $auth_r->post('/users/update')     ->to('users#update');
    $admin_r->get('/users/list')       ->to('users#list');
    $admin_r->get('/users/new')        ->to('users#add');
    $admin_r->post('/users/create')    ->to('users#create');
    $admin_r->get('/users/delete/:id') ->to('users#delete');
}

# build dsn
sub build_dsn {
    my $config = shift;

    return 'dbi:'
        . $config->{driver}
        . ':dbname='
        . $config->{dbname}
        . ';host='
        . $config->{dbhost}
        . ';port='
        . $config->{dbport};
}

1;

@@ users_model
% my $class = shift;
use utf8;
package <%= $class %>::Result::User;

use strict;
use warnings;

use base 'DBIx::Class::Core';

__PACKAGE__->load_components('InflateColumn::DateTime');
__PACKAGE__->table('users');

__PACKAGE__->add_columns(
    'id',
    {
        data_type         => 'integer',
        is_auto_increment => 1,
        is_nullable       => 0,
        sequence          => 'users_id_seq',
    },
    'login',
    { data_type => 'varchar', is_nullable => 0, size => 255 },
    'email',
    { data_type => 'varchar', is_nullable => 0, size => 255 },
    'password',
    { data_type => 'varchar', is_nullable => 0, size => 255 },
    'admin',
    { data_type => 'boolean', is_nullable => 0, default => 0 },
);

__PACKAGE__->set_primary_key('id');
__PACKAGE__->add_unique_constraint('users_email_key', ['email']);
__PACKAGE__->add_unique_constraint('users_login_key', ['login']);

1;

@@ migrate
% my $class = shift;
% my $name = shift;
#!/usr/bin/env perl

use strict;
use warnings;
use 5.012;
use lib 'lib';
use Getopt::Long qw(:config pass_through);
use <%= $class %>;

my $db = 'share/<%= $name %>.db';
my $driver = 'SQLite';
my $user = '';
my $pass = '';
my $host = '';
my $port = 0;
my $init = 0;

my $result = GetOptions(
    'h|host=s' => \$host,
    'p|port=i' => \$port,
    'u|user=s' => \$user,
    'p|pass=s' => \$pass,
    'd|db=s' => \$db,
    'm|driver=s' => \$driver,
    'init' => \$init,
);

my $dsn_head = "dbi:$driver:dbname=$db;";
my $dsn_host = $host ? "host=$host;" : '';
my $dsn_port = $port ? "port=$port;" : '';

my $dsn = $dsn_head . $dsn_host . $dsn_port;

$ENV{DBIC_MIGRATION_SCHEMA_CLASS} = '<%= $class %>';

eval {
    require DBIx::Class::Migration;
    DBIx::Class::Migration->import();
};

if ($@) {
    say "Run this script after installing DBIx::Class::Migration for database version management.";
    unless ($init) {
        say "To initialize the database anyway run ${0} --init";
        exit 1;
    }

    require <%= $class %>;
    <%= $class %>->import();
    my $schema = <%= $class %>->connect($dsn, $user, $pass);
    $schema->deploy;
    my $admin = do 'share/fixtures/1/all_tables/users/1.fix';
    $schema->resultset('User')->create($admin);
}
else {
    unshift @ARGV, ('--dsn', $dsn, '--username', $user, '--password', $pass);
    (require DBIx::Class::Migration::Script)->run_with_options;
}

@@ fixture
$HASH1 = {
           email    => 'admin@example.com',
           id       => 1,
           login    => 'admin',
           password => '$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.',
           admin    => 1
         };

@@ fixture_config
{
   "sets" : [
      {
         "quantity" : "all",
         "class" : "User"
      }
   ],
   "might_have" : {
      "fetch" : 0
   },
   "belongs_to" : {
      "fetch" : 0
   },
   "has_many" : {
      "fetch" : 0
   }
}

@@ login_form
%% layout 'bootstrap';
%% title 'Login';

%%= include 'elements/topnav'
%%= include 'elements/flash'

%%= form_for '/authenticate' => ( method => 'POST', class => 'well' ) => begin
    <label>Login</label>
    %%= text_field 'login', class => 'span3', type => 'text'
    <label>Password</label>
    %%= password_field 'password', class => 'span3'
    <br />
    %%= submit_button 'Login', class => 'btn btn-primary'
%% end

%%= include 'elements/footer'

@@ auth_controller
% my $class = shift;
package <%= $class %>;
use Mojo::Base 'Mojolicious::Controller';
use Crypt::Passwd::XS;

sub login {
    my $self = shift;
    $self->render();
}

sub authenticate {
    my $self = shift;

    my $login = $self->param('login');
    my $password = $self->param('password');

    if (my $user = $self->_authenticate_user($login, $password)){
        $self->session( authenticated => 1, user => {
            id    => $user->id,
            login => $user->login,
            email => $user->email,
            admin => $user->admin,
        });
        $self->flash( class => 'alert alert-info', message => 'Logged in!' );
        $self->redirect_to('/');
    }
    else {
        $self->flash( class => 'alert alert-error', message => 'Use "admin" and "password" to log in.' );
        $self->redirect_to('/login');
    }

}

sub logout {
    my $self = shift;

    $self->session( user => undef, authenticated => undef );
    $self->flash( class => 'alert alert-info', message => 'Logged out!' );

    $self->redirect_to('/');
}

sub _authenticate_user {
    my ($self, $login, $password) = @_;

    my $user = $self->model('User')->find({ login => $login });
    my $salt = (split '\$', $user->password)[2] if $user;

    # no salt, no user
    return 0 unless $salt;

    if ($user) {
        return $user if Crypt::Passwd::XS::unix_sha512_crypt($password, $salt) eq $user->password;
    }
    else {
        return 0;
    }
}

1;

@@ example_controller
% my $class = shift;
package <%= $class %>;
use Mojo::Base 'Mojolicious::Controller';

# This action will render a template
sub welcome {
    my $self = shift;

    $self->render();
}

1;

@@ users_controller
% my $class = shift;
package <%= $class %>;

use Mojo::Base 'Mojolicious::Controller';

use Email::Valid;
use Try::Tiny;
use String::Random;
use Crypt::Passwd::XS 'unix_sha512_crypt';

sub list {
    my $self = shift;

    $self->render( userlist => [$self->model('User')->all] );
}

sub add {
    my $self = shift;

    $self->render();
}

sub create {
    my $self = shift;

    my $record = {};

    if ($self->_validate_form){
        $record->{login} = $self->_trim($self->param('login'));
        $record->{email}    = $self->_trim($self->param('email'));
        $record->{password} = $self->_encrypt_password($self->param('password'));
        $record->{admin}    = $self->param('admin') || 0;

        try {
            $self->model('User')->create($record);
        }
        catch {
            $self->flash(class => 'alert alert-error', message => $!);
            $self->redirect_to($self->req->headers->referrer);
        };
        $self->redirect_to('/users/list');
    }
    else {
        $self->redirect_to($self->req->headers->referrer);
    }
}

sub delete {
    my $self = shift;

    my $user = $self->model('User')->find( $self->stash('id') );
    my $login = $user->login;

    if ($user->id != $self->session->{user}->{id}){
        $user->delete;
        $self->flash( class => 'alert alert-info', message => "$login deleted." );
    }
    else {
        $self->flash( class => 'alert alert-error', message => "You can not delete $login." );
    }

    $self->redirect_to('/users/list');
}

sub edit {
    my $self = shift;

    if (defined $self->stash('id')) {
        my $user = $self->model('User')->find($self->stash('id'));
        if ($user->id == $self->session->{user}->{id} || $self->session->{user}->{admin}) {
            $self->render( user => $user );
        }
        else {
            $self->flash( class => 'alert alert-error', message => 'Not authorized.' );
            $self->redirect_to($self->req->headers->referrer);
        }
    }
    else {
        $self->flash( class => 'alert alert-error', message => 'No user given.' );
        $self->redirect_to($self->req->headers->referrer);
    }
}

sub update {
    my $self = shift;

    my $record = {};

    if ($self->_validate_form){
        $record->{login} = $self->_trim($self->param('login'));
        $record->{email}    = $self->_trim($self->param('email'));
        $record->{password} = $self->_encrypt_password($self->param('password'));
        $record->{admin}    = $self->param('admin') || 0;

        if (defined $self->param('id')) {
            my $user = $self->model('User')->find($self->param('id'));
            if ($user->id == $self->session->{user}->{id} || $self->session->{user}->{admin}) {
                $record->{id} = $self->param('id');
                try {
                    $self->model('User')->update_or_create($record);
                    $self->flash(class => 'alert alert-notice', message => 'Updated ' . $user->login);
                }
                catch {
                    $self->flash(class => 'alert alert-error', message => $!);
                };
                $self->redirect_to($self->session->{user}->{admin} ? '/users/list' : '/');
            }
        }
        else {
            $self->flash(class => 'alert alert-error', message => 'No user given.');
            $self->redirect_to($self->session->{user}->{admin} ? '/users/list' : '/');
        }
    }
    else {
        $self->redirect_to($self->req->headers->referrer);
    }
}

sub _trim {
    my ($self, $string) = @_;
    $string =~ s/^\s*(.*)\s*$/$1/gmx if defined $string;

    return $string
}

sub _validate_form {
    my $self = shift;

    if ($self->_trim($self->param('login')) !~ /[a-zA-Z]{3,10}/){
        $self->flash(class => 'alert alert-error', message => $self->param('login') . ' does not match /[a-zA-Z]{3,10}/');
        return 0;
    }
    elsif ($self->param('password') ne $self->param('password_verify')){
        $self->flash(class => 'alert alert-error', message => 'Passwords do not match.');
        return 0;
    }
    elsif ($self->param('password') eq ''){
        $self->flash(class => 'alert alert-error', message => 'Password is empty.');
        return 0;
    }
    elsif (!Email::Valid->address($self->_trim($self->param('email')))){
        $self->flash(class => 'alert alert-error', message => 'You have to provide a valid email address.');
        return 0;
    }
    elsif ($self->param('admin')){
        unless ($self->session('user')->{admin}){
            $self->flash(class => 'alert alert-error', message => 'Only admins can create admins.');
            return 0;
        }
    }

    return 1;
}

sub _encrypt_password {
    my ($self, $plaintext) = @_;

    my $salt = String::Random::random_string('s' x 16);
    return Crypt::Passwd::XS::unix_sha512_crypt($plaintext, $salt);
}

1;

@@ user_list_template
%% layout 'bootstrap';
%% title 'Users';
%%= include 'elements/topnav'
%%= include 'elements/flash'

<table class="table table-striped">
    <thead>
        <th>User ID</th>
        <th>Login</th>
        <th>Email</th>
        <th>Admin</th>
        <th></th>
        <th></th>
    </thead>
    %% if (my $userlist = stash 'userlist'){
    <tbody>
        %% for my $user (@$userlist){
            <tr>
                <td><%%= $user->id %></td>
                <td><%%= $user->login %></td>
                <td><%%= $user->email %></td>
                <td><%%= $user->admin %></td>
                <td><a href="/users/edit/<%%= $user->id %>">edit</a></td>
                <td><a href="/users/delete/<%%= $user->id %>">delete</a></td>
            </tr>
        %% }
    </tbody>
    %% }
</table>

<a class="pull-right btn btn-primary" href="/users/new">Add User</a>

%%= include 'elements/footer'

@@ user_add_template
%% layout 'bootstrap';
%% title 'Edit User';
%%= include 'elements/topnav'
%%= include 'elements/flash'

%%= form_for '/users/create' => ( method => 'POST', class => 'well form-horizontal' ) => begin
    <div class="control-group">
        <label class="control-label">Login Name</label>
        <div class="controls">
                %%= text_field 'login', class => 'span3', type => 'text'
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Email Address</label>
        <div class="controls">
                %%= text_field 'email', class => 'span3', type => 'text'
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Password</label>
        <div class="controls">
                %%= password_field 'password', class => 'span3'
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Password Verification</label>
        <div class="controls">
                %%= password_field 'password_verify', class => 'span3'
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Admin</label>
        <div class="controls">
            <input type="checkbox" name="admin" />
        </div>
    </div>
    <div class="control-group">
        <div class="controls">
                %%= submit_button 'Create user', class => 'btn btn-primary'
        </div>
    </div>
%% end

%%= include 'elements/footer'

@@ user_edit_template
%% layout 'bootstrap';
%% title 'Add User';
%%= include 'elements/topnav'
%%= include 'elements/flash'
%% my $user = stash 'user';

%%= form_for '/users/update' => ( method => 'POST', class => 'well form-horizontal' ) => begin
    <div class="control-group">
        <label class="control-label">Login Name</label>
        <div class="controls">
                %%= text_field 'login', class => 'span3', type => 'text', value => $user->login
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Email Address</label>
        <div class="controls">
                %%= text_field 'email', class => 'span3', type => 'text', value => $user->email
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Password</label>
        <div class="controls">
                %%= password_field 'password', class => 'span3'
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Password Verification</label>
        <div class="controls">
                %%= password_field 'password_verify', class => 'span3'
        </div>
    </div>
    <div class="control-group">
        <label class="control-label">Admin</label>
        <div class="controls">
            <input type="checkbox" name="admin" <%%= 'checked' if $user->admin %> />
        </div>
    </div>
    %%= hidden_field 'id', $user->id
    <div class="control-group">
        <div class="controls">
                %%= submit_button 'Update user', class => 'btn btn-primary'
        </div>
    </div>
%% end

%%= include 'elements/footer'

@@ welcome_template
%% layout 'bootstrap';
%% title 'Welcome';
%%= include 'elements/topnav'
%%= include 'elements/flash'

<h1>Welcome to Mojolicious</h1>
This page was generated from the template "templates/example/welcome.html.ep"
and the layout "templates/layouts/bootstrap.html.ep",
<a href="<%%== url_for %>">click here</a> to reload the page or
<a href="/index.html">here</a> to move forward to a static page.

%%= include 'elements/footer'

@@ footer
<div class="navbar navbar-inverse navbar-fixed-bottom">
    <div class="navbar-inner">
        <div class="container">
            <ul class="nav">
            </ul>
            <ul class="nav pull-right">
            </ul>
        </div>
    </div>
</div>

@@ topnav
<div class="navbar navbar-inverse navbar-fixed-top">
    <div class="navbar-inner">
        <div class="container">
            <ul class="nav">
                %% if ( my $auth = session 'authenticated'){
                    %% my $user = session 'user';
                    <li><a href="/">Home</a></li>
                    %% if ( $user->{admin} ) {
                        <li><a href="/users/list">Users</a></li>
                    %% }
                %% }
            </ul>
            <ul class="nav pull-right">
                %% if ( my $auth = session 'authenticated'){
                    %% my $user = session 'user';
                    <li><a href="/logout">Logout <%%= $user->{login} %></a></li>
                %% } else {
                    <li><a href="/login">Login</a></li>
                %% }
            </ul>
        </div>
    </div>
</div>

@@ flash
%% if ( my $message = flash 'message' ){
    %% my $class = flash 'class' || 'alert alert-error';
    <div id="flash-msg" class="<%%= $class %>"><%%= $message %></div>
%% }

@@ layout
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title><%%= title %></title>
        %%= stylesheet '/bootstrap/css/bootstrap.min.css'
        %%= stylesheet '/style.css'
        %%= stylesheet '/bootstrap/css/bootstrap-responsive.min.css'
        %%= javascript '/bootstrap/js/bootstrap.min.js'
    </head>
    <body>
        <div class="container">
            <%%= content %>
        </div>
    </body>
</html>

@@ static
<!DOCTYPE html>
<html>
    <head>
        <link href="/bootstrap/css/bootstrap.min.css" rel="stylesheet">
        <link href="/style.css" rel="stylesheet">
        <link href="/bootstrap/css/bootstrap-responsive.min.css" rel="stylesheet">
        <script hrep="/bootstrap/js/bootstrap.min.js" type="text/javascript"></script>
        <title>Welcome to the Mojolicious real-time web framework!</title>
    </head>
    <body>
        <div id="container">
                <h3>Welcome to the Mojolicious real-time web framework!</h3>
                This is the static document "public/index.html",
                <a href="/">click here</a> to get back to the start.
        </div>
    </body>
</html>

@@ style
body { padding-top: 50px; }
@media screen and (max-width: 768px) {
    body { padding-top: 0px; }
}

@@ test
% my $class = shift;
use Mojo::Base -strict;

use Test::More;
use Test::Mojo;

my $t = Test::Mojo->new('<%= $class %>');
$t->ua->max_redirects(1);
$t->get_ok('/')->status_is(200)->content_like(qr/Please log in first!/i);
$t->get_ok('/login')->status_is(200)->content_like(qr/Login/i)->content_like(qr/Password/i);
$t->post_form_ok('/authenticate' => { login => 'admin', password => 'password' })
    ->status_is(200)
    ->get_ok('/')->status_is(200)->content_like(qr/Mojolicious/i);

done_testing();

@@ config
% my $db_name = shift;
database:
  driver: "SQLite"
  dbname: "share/<%= $db_name %>.db"
  dbuser: ""
  dbhost: ""
  dbpass: ""
  dbport: 0

loglevel: "debug"
hypnotoad:
  listen:
    - "http://*:8080"

@@ icons
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
m3wBeW40TQAAAABJRU5ErkJggg==

@@ icons_white
iVBORw0KGgoAAAANSUhEUgAAAdUAAACfCAMAAACY07N7AAAC2VBMVEX///8AAAAAAAD5+fn///8AAAD/
///9/f1tbW0AAAD///////////8AAAAAAAD////w8PD+/v729vYAAAD8/PwAAAAAAAD////////a2toA
AADCwsL09PT////////09PT39/f///8AAAAAAACzs7P9/f0AAADi4uKwsLD////////7+/vn5+f+/v7/
//8AAADt7e0AAADPz88AAAD9/f329vbt7e37+/vn5+f6+vrh4eGSkpL+/v7+/v7BwcGYmJh0dHTh4eHQ
0NAAAADz8/O7u7uhoaGAgID9/f3U1NRiYmL////V1dX4+Pjc3Nz6+vr7+/vp6en7+/v9/f39/f3R0dHy
8vL8/Pz4+Pjr6+v8/Py2trbGxsbl5eXu7u719fX9/f1lZWVnZ2fw8PC2trbg4OD39/f6+vrp6enl5eX6
+vr4+PjLy8v///+EhITx8fF4eHj39/fd3d35+fnIyMjS0tLs7Oz6+vre3t7i4uLm5ubz8/Obm5uoqKil
paXc3Nzu7u7////x8fHJycnw8PD////////e3t7Gxsa8vLzr6+vW1tbQ0NDi4uL5+fn09PTi4uLs7Oz1
9fW0tLT////9/f37+/v8/Pz6+vrm5uYAAADk5OT8/Pz39/ewsLCZmZn9/f3s7Oz8/PzBwcHp6en////a
2trw8PDw8PD19fXx8fH+/v74+Pj+/v6Ojo7i4uL7+/v5+fnc3Nz////y8vL6+vqfn5/t7e339/f29vbo
6Ojz8/P6+vr19fX19fWmpqbLy8v6+vr4+PjT09Pr6+v6+vrr6+uqqqrz8/Pt7e2ioqLPz8/a2trW1tai
oqLr6+vi4uL5+flVVVXNzc3////W1tbj4+Ph4eHq6ur8/Pz////29vb7+/vz8/P09PTMzMz////////5
+fn19fX////y8vL9/f0AAADZ2dn8/Pz7+/v8/Pzp6em/v7/7+/vq6urp6en+/v7////4ck/mAAAA8nRS
TlMAGgDUzwIP8SMQ759fCgUvqfDGFeIYA78fbxNTt98/hsV/BhdD4Q1rRI+vwo3ATxJTD18IoKWasozT
ETbQ4D40IX5hC6dAMR7RXydvEsRuotKLkZCATYahkzOxQlFqmbZwJiUhFWy1wyJYcXI7gB2XIEFbgjxg
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
sUuh7scAAAAASUVORK5CYII=

@@ bootstrap_min_js
LyohCiogQm9vdHN0cmFwLmpzIGJ5IEBmYXQgJiBAbWRvCiogQ29weXJpZ2h0IDIwMTIgVHdpdHRlciwg
SW5jLgoqIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMC50eHQKKi8KIWZ1
bmN0aW9uKGUpeyJ1c2Ugc3RyaWN0IjtlKGZ1bmN0aW9uKCl7ZS5zdXBwb3J0LnRyYW5zaXRpb249ZnVu
Y3Rpb24oKXt2YXIgZT1mdW5jdGlvbigpe3ZhciBlPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJvb3Rz
dHJhcCIpLHQ9e1dlYmtpdFRyYW5zaXRpb246IndlYmtpdFRyYW5zaXRpb25FbmQiLE1velRyYW5zaXRp
b246InRyYW5zaXRpb25lbmQiLE9UcmFuc2l0aW9uOiJvVHJhbnNpdGlvbkVuZCBvdHJhbnNpdGlvbmVu
ZCIsdHJhbnNpdGlvbjoidHJhbnNpdGlvbmVuZCJ9LG47Zm9yKG4gaW4gdClpZihlLnN0eWxlW25dIT09
dW5kZWZpbmVkKXJldHVybiB0W25dfSgpO3JldHVybiBlJiZ7ZW5kOmV9fSgpfSl9KHdpbmRvdy5qUXVl
cnkpLCFmdW5jdGlvbihlKXsidXNlIHN0cmljdCI7dmFyIHQ9J1tkYXRhLWRpc21pc3M9ImFsZXJ0Il0n
LG49ZnVuY3Rpb24obil7ZShuKS5vbigiY2xpY2siLHQsdGhpcy5jbG9zZSl9O24ucHJvdG90eXBlLmNs
b3NlPWZ1bmN0aW9uKHQpe2Z1bmN0aW9uIHMoKXtpLnRyaWdnZXIoImNsb3NlZCIpLnJlbW92ZSgpfXZh
ciBuPWUodGhpcykscj1uLmF0dHIoImRhdGEtdGFyZ2V0IiksaTtyfHwocj1uLmF0dHIoImhyZWYiKSxy
PXImJnIucmVwbGFjZSgvLiooPz0jW15cc10qJCkvLCIiKSksaT1lKHIpLHQmJnQucHJldmVudERlZmF1
bHQoKSxpLmxlbmd0aHx8KGk9bi5oYXNDbGFzcygiYWxlcnQiKT9uOm4ucGFyZW50KCkpLGkudHJpZ2dl
cih0PWUuRXZlbnQoImNsb3NlIikpO2lmKHQuaXNEZWZhdWx0UHJldmVudGVkKCkpcmV0dXJuO2kucmVt
b3ZlQ2xhc3MoImluIiksZS5zdXBwb3J0LnRyYW5zaXRpb24mJmkuaGFzQ2xhc3MoImZhZGUiKT9pLm9u
KGUuc3VwcG9ydC50cmFuc2l0aW9uLmVuZCxzKTpzKCl9O3ZhciByPWUuZm4uYWxlcnQ7ZS5mbi5hbGVy
dD1mdW5jdGlvbih0KXtyZXR1cm4gdGhpcy5lYWNoKGZ1bmN0aW9uKCl7dmFyIHI9ZSh0aGlzKSxpPXIu
ZGF0YSgiYWxlcnQiKTtpfHxyLmRhdGEoImFsZXJ0IixpPW5ldyBuKHRoaXMpKSx0eXBlb2YgdD09InN0
cmluZyImJmlbdF0uY2FsbChyKX0pfSxlLmZuLmFsZXJ0LkNvbnN0cnVjdG9yPW4sZS5mbi5hbGVydC5u
b0NvbmZsaWN0PWZ1bmN0aW9uKCl7cmV0dXJuIGUuZm4uYWxlcnQ9cix0aGlzfSxlKGRvY3VtZW50KS5v
bigiY2xpY2suYWxlcnQuZGF0YS1hcGkiLHQsbi5wcm90b3R5cGUuY2xvc2UpfSh3aW5kb3cualF1ZXJ5
KSwhZnVuY3Rpb24oZSl7InVzZSBzdHJpY3QiO3ZhciB0PWZ1bmN0aW9uKHQsbil7dGhpcy4kZWxlbWVu
dD1lKHQpLHRoaXMub3B0aW9ucz1lLmV4dGVuZCh7fSxlLmZuLmJ1dHRvbi5kZWZhdWx0cyxuKX07dC5w
cm90b3R5cGUuc2V0U3RhdGU9ZnVuY3Rpb24oZSl7dmFyIHQ9ImRpc2FibGVkIixuPXRoaXMuJGVsZW1l
bnQscj1uLmRhdGEoKSxpPW4uaXMoImlucHV0Iik/InZhbCI6Imh0bWwiO2UrPSJUZXh0IixyLnJlc2V0
VGV4dHx8bi5kYXRhKCJyZXNldFRleHQiLG5baV0oKSksbltpXShyW2VdfHx0aGlzLm9wdGlvbnNbZV0p
LHNldFRpbWVvdXQoZnVuY3Rpb24oKXtlPT0ibG9hZGluZ1RleHQiP24uYWRkQ2xhc3ModCkuYXR0cih0
LHQpOm4ucmVtb3ZlQ2xhc3ModCkucmVtb3ZlQXR0cih0KX0sMCl9LHQucHJvdG90eXBlLnRvZ2dsZT1m
dW5jdGlvbigpe3ZhciBlPXRoaXMuJGVsZW1lbnQuY2xvc2VzdCgnW2RhdGEtdG9nZ2xlPSJidXR0b25z
LXJhZGlvIl0nKTtlJiZlLmZpbmQoIi5hY3RpdmUiKS5yZW1vdmVDbGFzcygiYWN0aXZlIiksdGhpcy4k
ZWxlbWVudC50b2dnbGVDbGFzcygiYWN0aXZlIil9O3ZhciBuPWUuZm4uYnV0dG9uO2UuZm4uYnV0dG9u
PWZ1bmN0aW9uKG4pe3JldHVybiB0aGlzLmVhY2goZnVuY3Rpb24oKXt2YXIgcj1lKHRoaXMpLGk9ci5k
YXRhKCJidXR0b24iKSxzPXR5cGVvZiBuPT0ib2JqZWN0IiYmbjtpfHxyLmRhdGEoImJ1dHRvbiIsaT1u
ZXcgdCh0aGlzLHMpKSxuPT0idG9nZ2xlIj9pLnRvZ2dsZSgpOm4mJmkuc2V0U3RhdGUobil9KX0sZS5m
bi5idXR0b24uZGVmYXVsdHM9e2xvYWRpbmdUZXh0OiJsb2FkaW5nLi4uIn0sZS5mbi5idXR0b24uQ29u
c3RydWN0b3I9dCxlLmZuLmJ1dHRvbi5ub0NvbmZsaWN0PWZ1bmN0aW9uKCl7cmV0dXJuIGUuZm4uYnV0
dG9uPW4sdGhpc30sZShkb2N1bWVudCkub24oImNsaWNrLmJ1dHRvbi5kYXRhLWFwaSIsIltkYXRhLXRv
Z2dsZV49YnV0dG9uXSIsZnVuY3Rpb24odCl7dmFyIG49ZSh0LnRhcmdldCk7bi5oYXNDbGFzcygiYnRu
Iil8fChuPW4uY2xvc2VzdCgiLmJ0biIpKSxuLmJ1dHRvbigidG9nZ2xlIil9KX0od2luZG93LmpRdWVy
eSksIWZ1bmN0aW9uKGUpeyJ1c2Ugc3RyaWN0Ijt2YXIgdD1mdW5jdGlvbih0LG4pe3RoaXMuJGVsZW1l
bnQ9ZSh0KSx0aGlzLiRpbmRpY2F0b3JzPXRoaXMuJGVsZW1lbnQuZmluZCgiLmNhcm91c2VsLWluZGlj
YXRvcnMiKSx0aGlzLm9wdGlvbnM9bix0aGlzLm9wdGlvbnMucGF1c2U9PSJob3ZlciImJnRoaXMuJGVs
ZW1lbnQub24oIm1vdXNlZW50ZXIiLGUucHJveHkodGhpcy5wYXVzZSx0aGlzKSkub24oIm1vdXNlbGVh
dmUiLGUucHJveHkodGhpcy5jeWNsZSx0aGlzKSl9O3QucHJvdG90eXBlPXtjeWNsZTpmdW5jdGlvbih0
KXtyZXR1cm4gdHx8KHRoaXMucGF1c2VkPSExKSx0aGlzLmludGVydmFsJiZjbGVhckludGVydmFsKHRo
aXMuaW50ZXJ2YWwpLHRoaXMub3B0aW9ucy5pbnRlcnZhbCYmIXRoaXMucGF1c2VkJiYodGhpcy5pbnRl
cnZhbD1zZXRJbnRlcnZhbChlLnByb3h5KHRoaXMubmV4dCx0aGlzKSx0aGlzLm9wdGlvbnMuaW50ZXJ2
YWwpKSx0aGlzfSxnZXRBY3RpdmVJbmRleDpmdW5jdGlvbigpe3JldHVybiB0aGlzLiRhY3RpdmU9dGhp
cy4kZWxlbWVudC5maW5kKCIuaXRlbS5hY3RpdmUiKSx0aGlzLiRpdGVtcz10aGlzLiRhY3RpdmUucGFy
ZW50KCkuY2hpbGRyZW4oKSx0aGlzLiRpdGVtcy5pbmRleCh0aGlzLiRhY3RpdmUpfSx0bzpmdW5jdGlv
bih0KXt2YXIgbj10aGlzLmdldEFjdGl2ZUluZGV4KCkscj10aGlzO2lmKHQ+dGhpcy4kaXRlbXMubGVu
Z3RoLTF8fHQ8MClyZXR1cm47cmV0dXJuIHRoaXMuc2xpZGluZz90aGlzLiRlbGVtZW50Lm9uZSgic2xp
ZCIsZnVuY3Rpb24oKXtyLnRvKHQpfSk6bj09dD90aGlzLnBhdXNlKCkuY3ljbGUoKTp0aGlzLnNsaWRl
KHQ+bj8ibmV4dCI6InByZXYiLGUodGhpcy4kaXRlbXNbdF0pKX0scGF1c2U6ZnVuY3Rpb24odCl7cmV0
dXJuIHR8fCh0aGlzLnBhdXNlZD0hMCksdGhpcy4kZWxlbWVudC5maW5kKCIubmV4dCwgLnByZXYiKS5s
ZW5ndGgmJmUuc3VwcG9ydC50cmFuc2l0aW9uLmVuZCYmKHRoaXMuJGVsZW1lbnQudHJpZ2dlcihlLnN1
cHBvcnQudHJhbnNpdGlvbi5lbmQpLHRoaXMuY3ljbGUoKSksY2xlYXJJbnRlcnZhbCh0aGlzLmludGVy
dmFsKSx0aGlzLmludGVydmFsPW51bGwsdGhpc30sbmV4dDpmdW5jdGlvbigpe2lmKHRoaXMuc2xpZGlu
ZylyZXR1cm47cmV0dXJuIHRoaXMuc2xpZGUoIm5leHQiKX0scHJldjpmdW5jdGlvbigpe2lmKHRoaXMu
c2xpZGluZylyZXR1cm47cmV0dXJuIHRoaXMuc2xpZGUoInByZXYiKX0sc2xpZGU6ZnVuY3Rpb24odCxu
KXt2YXIgcj10aGlzLiRlbGVtZW50LmZpbmQoIi5pdGVtLmFjdGl2ZSIpLGk9bnx8clt0XSgpLHM9dGhp
cy5pbnRlcnZhbCxvPXQ9PSJuZXh0Ij8ibGVmdCI6InJpZ2h0Iix1PXQ9PSJuZXh0Ij8iZmlyc3QiOiJs
YXN0IixhPXRoaXMsZjt0aGlzLnNsaWRpbmc9ITAscyYmdGhpcy5wYXVzZSgpLGk9aS5sZW5ndGg/aTp0
aGlzLiRlbGVtZW50LmZpbmQoIi5pdGVtIilbdV0oKSxmPWUuRXZlbnQoInNsaWRlIix7cmVsYXRlZFRh
cmdldDppWzBdLGRpcmVjdGlvbjpvfSk7aWYoaS5oYXNDbGFzcygiYWN0aXZlIikpcmV0dXJuO3RoaXMu
JGluZGljYXRvcnMubGVuZ3RoJiYodGhpcy4kaW5kaWNhdG9ycy5maW5kKCIuYWN0aXZlIikucmVtb3Zl
Q2xhc3MoImFjdGl2ZSIpLHRoaXMuJGVsZW1lbnQub25lKCJzbGlkIixmdW5jdGlvbigpe3ZhciB0PWUo
YS4kaW5kaWNhdG9ycy5jaGlsZHJlbigpW2EuZ2V0QWN0aXZlSW5kZXgoKV0pO3QmJnQuYWRkQ2xhc3Mo
ImFjdGl2ZSIpfSkpO2lmKGUuc3VwcG9ydC50cmFuc2l0aW9uJiZ0aGlzLiRlbGVtZW50Lmhhc0NsYXNz
KCJzbGlkZSIpKXt0aGlzLiRlbGVtZW50LnRyaWdnZXIoZik7aWYoZi5pc0RlZmF1bHRQcmV2ZW50ZWQo
KSlyZXR1cm47aS5hZGRDbGFzcyh0KSxpWzBdLm9mZnNldFdpZHRoLHIuYWRkQ2xhc3MobyksaS5hZGRD
bGFzcyhvKSx0aGlzLiRlbGVtZW50Lm9uZShlLnN1cHBvcnQudHJhbnNpdGlvbi5lbmQsZnVuY3Rpb24o
KXtpLnJlbW92ZUNsYXNzKFt0LG9dLmpvaW4oIiAiKSkuYWRkQ2xhc3MoImFjdGl2ZSIpLHIucmVtb3Zl
Q2xhc3MoWyJhY3RpdmUiLG9dLmpvaW4oIiAiKSksYS5zbGlkaW5nPSExLHNldFRpbWVvdXQoZnVuY3Rp
b24oKXthLiRlbGVtZW50LnRyaWdnZXIoInNsaWQiKX0sMCl9KX1lbHNle3RoaXMuJGVsZW1lbnQudHJp
Z2dlcihmKTtpZihmLmlzRGVmYXVsdFByZXZlbnRlZCgpKXJldHVybjtyLnJlbW92ZUNsYXNzKCJhY3Rp
dmUiKSxpLmFkZENsYXNzKCJhY3RpdmUiKSx0aGlzLnNsaWRpbmc9ITEsdGhpcy4kZWxlbWVudC50cmln
Z2VyKCJzbGlkIil9cmV0dXJuIHMmJnRoaXMuY3ljbGUoKSx0aGlzfX07dmFyIG49ZS5mbi5jYXJvdXNl
bDtlLmZuLmNhcm91c2VsPWZ1bmN0aW9uKG4pe3JldHVybiB0aGlzLmVhY2goZnVuY3Rpb24oKXt2YXIg
cj1lKHRoaXMpLGk9ci5kYXRhKCJjYXJvdXNlbCIpLHM9ZS5leHRlbmQoe30sZS5mbi5jYXJvdXNlbC5k
ZWZhdWx0cyx0eXBlb2Ygbj09Im9iamVjdCImJm4pLG89dHlwZW9mIG49PSJzdHJpbmciP246cy5zbGlk
ZTtpfHxyLmRhdGEoImNhcm91c2VsIixpPW5ldyB0KHRoaXMscykpLHR5cGVvZiBuPT0ibnVtYmVyIj9p
LnRvKG4pOm8/aVtvXSgpOnMuaW50ZXJ2YWwmJmkucGF1c2UoKS5jeWNsZSgpfSl9LGUuZm4uY2Fyb3Vz
ZWwuZGVmYXVsdHM9e2ludGVydmFsOjVlMyxwYXVzZToiaG92ZXIifSxlLmZuLmNhcm91c2VsLkNvbnN0
cnVjdG9yPXQsZS5mbi5jYXJvdXNlbC5ub0NvbmZsaWN0PWZ1bmN0aW9uKCl7cmV0dXJuIGUuZm4uY2Fy
b3VzZWw9bix0aGlzfSxlKGRvY3VtZW50KS5vbigiY2xpY2suY2Fyb3VzZWwuZGF0YS1hcGkiLCJbZGF0
YS1zbGlkZV0sIFtkYXRhLXNsaWRlLXRvXSIsZnVuY3Rpb24odCl7dmFyIG49ZSh0aGlzKSxyLGk9ZShu
LmF0dHIoImRhdGEtdGFyZ2V0Iil8fChyPW4uYXR0cigiaHJlZiIpKSYmci5yZXBsYWNlKC8uKig/PSNb
XlxzXSskKS8sIiIpKSxzPWUuZXh0ZW5kKHt9LGkuZGF0YSgpLG4uZGF0YSgpKSxvO2kuY2Fyb3VzZWwo
cyksKG89bi5hdHRyKCJkYXRhLXNsaWRlLXRvIikpJiZpLmRhdGEoImNhcm91c2VsIikucGF1c2UoKS50
byhvKS5jeWNsZSgpLHQucHJldmVudERlZmF1bHQoKX0pfSh3aW5kb3cualF1ZXJ5KSwhZnVuY3Rpb24o
ZSl7InVzZSBzdHJpY3QiO3ZhciB0PWZ1bmN0aW9uKHQsbil7dGhpcy4kZWxlbWVudD1lKHQpLHRoaXMu
b3B0aW9ucz1lLmV4dGVuZCh7fSxlLmZuLmNvbGxhcHNlLmRlZmF1bHRzLG4pLHRoaXMub3B0aW9ucy5w
YXJlbnQmJih0aGlzLiRwYXJlbnQ9ZSh0aGlzLm9wdGlvbnMucGFyZW50KSksdGhpcy5vcHRpb25zLnRv
Z2dsZSYmdGhpcy50b2dnbGUoKX07dC5wcm90b3R5cGU9e2NvbnN0cnVjdG9yOnQsZGltZW5zaW9uOmZ1
bmN0aW9uKCl7dmFyIGU9dGhpcy4kZWxlbWVudC5oYXNDbGFzcygid2lkdGgiKTtyZXR1cm4gZT8id2lk
dGgiOiJoZWlnaHQifSxzaG93OmZ1bmN0aW9uKCl7dmFyIHQsbixyLGk7aWYodGhpcy50cmFuc2l0aW9u
aW5nfHx0aGlzLiRlbGVtZW50Lmhhc0NsYXNzKCJpbiIpKXJldHVybjt0PXRoaXMuZGltZW5zaW9uKCks
bj1lLmNhbWVsQ2FzZShbInNjcm9sbCIsdF0uam9pbigiLSIpKSxyPXRoaXMuJHBhcmVudCYmdGhpcy4k
cGFyZW50LmZpbmQoIj4gLmFjY29yZGlvbi1ncm91cCA+IC5pbiIpO2lmKHImJnIubGVuZ3RoKXtpPXIu
ZGF0YSgiY29sbGFwc2UiKTtpZihpJiZpLnRyYW5zaXRpb25pbmcpcmV0dXJuO3IuY29sbGFwc2UoImhp
ZGUiKSxpfHxyLmRhdGEoImNvbGxhcHNlIixudWxsKX10aGlzLiRlbGVtZW50W3RdKDApLHRoaXMudHJh
bnNpdGlvbigiYWRkQ2xhc3MiLGUuRXZlbnQoInNob3ciKSwic2hvd24iKSxlLnN1cHBvcnQudHJhbnNp
dGlvbiYmdGhpcy4kZWxlbWVudFt0XSh0aGlzLiRlbGVtZW50WzBdW25dKX0saGlkZTpmdW5jdGlvbigp
e3ZhciB0O2lmKHRoaXMudHJhbnNpdGlvbmluZ3x8IXRoaXMuJGVsZW1lbnQuaGFzQ2xhc3MoImluIikp
cmV0dXJuO3Q9dGhpcy5kaW1lbnNpb24oKSx0aGlzLnJlc2V0KHRoaXMuJGVsZW1lbnRbdF0oKSksdGhp
cy50cmFuc2l0aW9uKCJyZW1vdmVDbGFzcyIsZS5FdmVudCgiaGlkZSIpLCJoaWRkZW4iKSx0aGlzLiRl
bGVtZW50W3RdKDApfSxyZXNldDpmdW5jdGlvbihlKXt2YXIgdD10aGlzLmRpbWVuc2lvbigpO3JldHVy
biB0aGlzLiRlbGVtZW50LnJlbW92ZUNsYXNzKCJjb2xsYXBzZSIpW3RdKGV8fCJhdXRvIilbMF0ub2Zm
c2V0V2lkdGgsdGhpcy4kZWxlbWVudFtlIT09bnVsbD8iYWRkQ2xhc3MiOiJyZW1vdmVDbGFzcyJdKCJj
b2xsYXBzZSIpLHRoaXN9LHRyYW5zaXRpb246ZnVuY3Rpb24odCxuLHIpe3ZhciBpPXRoaXMscz1mdW5j
dGlvbigpe24udHlwZT09InNob3ciJiZpLnJlc2V0KCksaS50cmFuc2l0aW9uaW5nPTAsaS4kZWxlbWVu
dC50cmlnZ2VyKHIpfTt0aGlzLiRlbGVtZW50LnRyaWdnZXIobik7aWYobi5pc0RlZmF1bHRQcmV2ZW50
ZWQoKSlyZXR1cm47dGhpcy50cmFuc2l0aW9uaW5nPTEsdGhpcy4kZWxlbWVudFt0XSgiaW4iKSxlLnN1
cHBvcnQudHJhbnNpdGlvbiYmdGhpcy4kZWxlbWVudC5oYXNDbGFzcygiY29sbGFwc2UiKT90aGlzLiRl
bGVtZW50Lm9uZShlLnN1cHBvcnQudHJhbnNpdGlvbi5lbmQscyk6cygpfSx0b2dnbGU6ZnVuY3Rpb24o
KXt0aGlzW3RoaXMuJGVsZW1lbnQuaGFzQ2xhc3MoImluIik/ImhpZGUiOiJzaG93Il0oKX19O3ZhciBu
PWUuZm4uY29sbGFwc2U7ZS5mbi5jb2xsYXBzZT1mdW5jdGlvbihuKXtyZXR1cm4gdGhpcy5lYWNoKGZ1
bmN0aW9uKCl7dmFyIHI9ZSh0aGlzKSxpPXIuZGF0YSgiY29sbGFwc2UiKSxzPWUuZXh0ZW5kKHt9LGUu
Zm4uY29sbGFwc2UuZGVmYXVsdHMsci5kYXRhKCksdHlwZW9mIG49PSJvYmplY3QiJiZuKTtpfHxyLmRh
dGEoImNvbGxhcHNlIixpPW5ldyB0KHRoaXMscykpLHR5cGVvZiBuPT0ic3RyaW5nIiYmaVtuXSgpfSl9
LGUuZm4uY29sbGFwc2UuZGVmYXVsdHM9e3RvZ2dsZTohMH0sZS5mbi5jb2xsYXBzZS5Db25zdHJ1Y3Rv
cj10LGUuZm4uY29sbGFwc2Uubm9Db25mbGljdD1mdW5jdGlvbigpe3JldHVybiBlLmZuLmNvbGxhcHNl
PW4sdGhpc30sZShkb2N1bWVudCkub24oImNsaWNrLmNvbGxhcHNlLmRhdGEtYXBpIiwiW2RhdGEtdG9n
Z2xlPWNvbGxhcHNlXSIsZnVuY3Rpb24odCl7dmFyIG49ZSh0aGlzKSxyLGk9bi5hdHRyKCJkYXRhLXRh
cmdldCIpfHx0LnByZXZlbnREZWZhdWx0KCl8fChyPW4uYXR0cigiaHJlZiIpKSYmci5yZXBsYWNlKC8u
Kig/PSNbXlxzXSskKS8sIiIpLHM9ZShpKS5kYXRhKCJjb2xsYXBzZSIpPyJ0b2dnbGUiOm4uZGF0YSgp
O25bZShpKS5oYXNDbGFzcygiaW4iKT8iYWRkQ2xhc3MiOiJyZW1vdmVDbGFzcyJdKCJjb2xsYXBzZWQi
KSxlKGkpLmNvbGxhcHNlKHMpfSl9KHdpbmRvdy5qUXVlcnkpLCFmdW5jdGlvbihlKXsidXNlIHN0cmlj
dCI7ZnVuY3Rpb24gcigpe2UodCkuZWFjaChmdW5jdGlvbigpe2koZSh0aGlzKSkucmVtb3ZlQ2xhc3Mo
Im9wZW4iKX0pfWZ1bmN0aW9uIGkodCl7dmFyIG49dC5hdHRyKCJkYXRhLXRhcmdldCIpLHI7bnx8KG49
dC5hdHRyKCJocmVmIiksbj1uJiYvIy8udGVzdChuKSYmbi5yZXBsYWNlKC8uKig/PSNbXlxzXSokKS8s
IiIpKSxyPW4mJmUobik7aWYoIXJ8fCFyLmxlbmd0aClyPXQucGFyZW50KCk7cmV0dXJuIHJ9dmFyIHQ9
IltkYXRhLXRvZ2dsZT1kcm9wZG93bl0iLG49ZnVuY3Rpb24odCl7dmFyIG49ZSh0KS5vbigiY2xpY2su
ZHJvcGRvd24uZGF0YS1hcGkiLHRoaXMudG9nZ2xlKTtlKCJodG1sIikub24oImNsaWNrLmRyb3Bkb3du
LmRhdGEtYXBpIixmdW5jdGlvbigpe24ucGFyZW50KCkucmVtb3ZlQ2xhc3MoIm9wZW4iKX0pfTtuLnBy
b3RvdHlwZT17Y29uc3RydWN0b3I6bix0b2dnbGU6ZnVuY3Rpb24odCl7dmFyIG49ZSh0aGlzKSxzLG87
aWYobi5pcygiLmRpc2FibGVkLCA6ZGlzYWJsZWQiKSlyZXR1cm47cmV0dXJuIHM9aShuKSxvPXMuaGFz
Q2xhc3MoIm9wZW4iKSxyKCksb3x8cy50b2dnbGVDbGFzcygib3BlbiIpLG4uZm9jdXMoKSwhMX0sa2V5
ZG93bjpmdW5jdGlvbihuKXt2YXIgcixzLG8sdSxhLGY7aWYoIS8oMzh8NDB8MjcpLy50ZXN0KG4ua2V5
Q29kZSkpcmV0dXJuO3I9ZSh0aGlzKSxuLnByZXZlbnREZWZhdWx0KCksbi5zdG9wUHJvcGFnYXRpb24o
KTtpZihyLmlzKCIuZGlzYWJsZWQsIDpkaXNhYmxlZCIpKXJldHVybjt1PWkociksYT11Lmhhc0NsYXNz
KCJvcGVuIik7aWYoIWF8fGEmJm4ua2V5Q29kZT09MjcpcmV0dXJuIG4ud2hpY2g9PTI3JiZ1LmZpbmQo
dCkuZm9jdXMoKSxyLmNsaWNrKCk7cz1lKCJbcm9sZT1tZW51XSBsaTpub3QoLmRpdmlkZXIpOnZpc2li
bGUgYSIsdSk7aWYoIXMubGVuZ3RoKXJldHVybjtmPXMuaW5kZXgocy5maWx0ZXIoIjpmb2N1cyIpKSxu
LmtleUNvZGU9PTM4JiZmPjAmJmYtLSxuLmtleUNvZGU9PTQwJiZmPHMubGVuZ3RoLTEmJmYrKyx+Znx8
KGY9MCkscy5lcShmKS5mb2N1cygpfX07dmFyIHM9ZS5mbi5kcm9wZG93bjtlLmZuLmRyb3Bkb3duPWZ1
bmN0aW9uKHQpe3JldHVybiB0aGlzLmVhY2goZnVuY3Rpb24oKXt2YXIgcj1lKHRoaXMpLGk9ci5kYXRh
KCJkcm9wZG93biIpO2l8fHIuZGF0YSgiZHJvcGRvd24iLGk9bmV3IG4odGhpcykpLHR5cGVvZiB0PT0i
c3RyaW5nIiYmaVt0XS5jYWxsKHIpfSl9LGUuZm4uZHJvcGRvd24uQ29uc3RydWN0b3I9bixlLmZuLmRy
b3Bkb3duLm5vQ29uZmxpY3Q9ZnVuY3Rpb24oKXtyZXR1cm4gZS5mbi5kcm9wZG93bj1zLHRoaXN9LGUo
ZG9jdW1lbnQpLm9uKCJjbGljay5kcm9wZG93bi5kYXRhLWFwaSIscikub24oImNsaWNrLmRyb3Bkb3du
LmRhdGEtYXBpIiwiLmRyb3Bkb3duIGZvcm0iLGZ1bmN0aW9uKGUpe2Uuc3RvcFByb3BhZ2F0aW9uKCl9
KS5vbigiLmRyb3Bkb3duLW1lbnUiLGZ1bmN0aW9uKGUpe2Uuc3RvcFByb3BhZ2F0aW9uKCl9KS5vbigi
Y2xpY2suZHJvcGRvd24uZGF0YS1hcGkiLHQsbi5wcm90b3R5cGUudG9nZ2xlKS5vbigia2V5ZG93bi5k
cm9wZG93bi5kYXRhLWFwaSIsdCsiLCBbcm9sZT1tZW51XSIsbi5wcm90b3R5cGUua2V5ZG93bil9KHdp
bmRvdy5qUXVlcnkpLCFmdW5jdGlvbihlKXsidXNlIHN0cmljdCI7dmFyIHQ9ZnVuY3Rpb24odCxuKXt0
aGlzLm9wdGlvbnM9bix0aGlzLiRlbGVtZW50PWUodCkuZGVsZWdhdGUoJ1tkYXRhLWRpc21pc3M9Im1v
ZGFsIl0nLCJjbGljay5kaXNtaXNzLm1vZGFsIixlLnByb3h5KHRoaXMuaGlkZSx0aGlzKSksdGhpcy5v
cHRpb25zLnJlbW90ZSYmdGhpcy4kZWxlbWVudC5maW5kKCIubW9kYWwtYm9keSIpLmxvYWQodGhpcy5v
cHRpb25zLnJlbW90ZSl9O3QucHJvdG90eXBlPXtjb25zdHJ1Y3Rvcjp0LHRvZ2dsZTpmdW5jdGlvbigp
e3JldHVybiB0aGlzW3RoaXMuaXNTaG93bj8iaGlkZSI6InNob3ciXSgpfSxzaG93OmZ1bmN0aW9uKCl7
dmFyIHQ9dGhpcyxuPWUuRXZlbnQoInNob3ciKTt0aGlzLiRlbGVtZW50LnRyaWdnZXIobik7aWYodGhp
cy5pc1Nob3dufHxuLmlzRGVmYXVsdFByZXZlbnRlZCgpKXJldHVybjt0aGlzLmlzU2hvd249ITAsdGhp
cy5lc2NhcGUoKSx0aGlzLmJhY2tkcm9wKGZ1bmN0aW9uKCl7dmFyIG49ZS5zdXBwb3J0LnRyYW5zaXRp
b24mJnQuJGVsZW1lbnQuaGFzQ2xhc3MoImZhZGUiKTt0LiRlbGVtZW50LnBhcmVudCgpLmxlbmd0aHx8
dC4kZWxlbWVudC5hcHBlbmRUbyhkb2N1bWVudC5ib2R5KSx0LiRlbGVtZW50LnNob3coKSxuJiZ0LiRl
bGVtZW50WzBdLm9mZnNldFdpZHRoLHQuJGVsZW1lbnQuYWRkQ2xhc3MoImluIikuYXR0cigiYXJpYS1o
aWRkZW4iLCExKSx0LmVuZm9yY2VGb2N1cygpLG4/dC4kZWxlbWVudC5vbmUoZS5zdXBwb3J0LnRyYW5z
aXRpb24uZW5kLGZ1bmN0aW9uKCl7dC4kZWxlbWVudC5mb2N1cygpLnRyaWdnZXIoInNob3duIil9KTp0
LiRlbGVtZW50LmZvY3VzKCkudHJpZ2dlcigic2hvd24iKX0pfSxoaWRlOmZ1bmN0aW9uKHQpe3QmJnQu
cHJldmVudERlZmF1bHQoKTt2YXIgbj10aGlzO3Q9ZS5FdmVudCgiaGlkZSIpLHRoaXMuJGVsZW1lbnQu
dHJpZ2dlcih0KTtpZighdGhpcy5pc1Nob3dufHx0LmlzRGVmYXVsdFByZXZlbnRlZCgpKXJldHVybjt0
aGlzLmlzU2hvd249ITEsdGhpcy5lc2NhcGUoKSxlKGRvY3VtZW50KS5vZmYoImZvY3VzaW4ubW9kYWwi
KSx0aGlzLiRlbGVtZW50LnJlbW92ZUNsYXNzKCJpbiIpLmF0dHIoImFyaWEtaGlkZGVuIiwhMCksZS5z
dXBwb3J0LnRyYW5zaXRpb24mJnRoaXMuJGVsZW1lbnQuaGFzQ2xhc3MoImZhZGUiKT90aGlzLmhpZGVX
aXRoVHJhbnNpdGlvbigpOnRoaXMuaGlkZU1vZGFsKCl9LGVuZm9yY2VGb2N1czpmdW5jdGlvbigpe3Zh
ciB0PXRoaXM7ZShkb2N1bWVudCkub24oImZvY3VzaW4ubW9kYWwiLGZ1bmN0aW9uKGUpe3QuJGVsZW1l
bnRbMF0hPT1lLnRhcmdldCYmIXQuJGVsZW1lbnQuaGFzKGUudGFyZ2V0KS5sZW5ndGgmJnQuJGVsZW1l
bnQuZm9jdXMoKX0pfSxlc2NhcGU6ZnVuY3Rpb24oKXt2YXIgZT10aGlzO3RoaXMuaXNTaG93biYmdGhp
cy5vcHRpb25zLmtleWJvYXJkP3RoaXMuJGVsZW1lbnQub24oImtleXVwLmRpc21pc3MubW9kYWwiLGZ1
bmN0aW9uKHQpe3Qud2hpY2g9PTI3JiZlLmhpZGUoKX0pOnRoaXMuaXNTaG93bnx8dGhpcy4kZWxlbWVu
dC5vZmYoImtleXVwLmRpc21pc3MubW9kYWwiKX0saGlkZVdpdGhUcmFuc2l0aW9uOmZ1bmN0aW9uKCl7
dmFyIHQ9dGhpcyxuPXNldFRpbWVvdXQoZnVuY3Rpb24oKXt0LiRlbGVtZW50Lm9mZihlLnN1cHBvcnQu
dHJhbnNpdGlvbi5lbmQpLHQuaGlkZU1vZGFsKCl9LDUwMCk7dGhpcy4kZWxlbWVudC5vbmUoZS5zdXBw
b3J0LnRyYW5zaXRpb24uZW5kLGZ1bmN0aW9uKCl7Y2xlYXJUaW1lb3V0KG4pLHQuaGlkZU1vZGFsKCl9
KX0saGlkZU1vZGFsOmZ1bmN0aW9uKCl7dmFyIGU9dGhpczt0aGlzLiRlbGVtZW50LmhpZGUoKSx0aGlz
LmJhY2tkcm9wKGZ1bmN0aW9uKCl7ZS5yZW1vdmVCYWNrZHJvcCgpLGUuJGVsZW1lbnQudHJpZ2dlcigi
aGlkZGVuIil9KX0scmVtb3ZlQmFja2Ryb3A6ZnVuY3Rpb24oKXt0aGlzLiRiYWNrZHJvcC5yZW1vdmUo
KSx0aGlzLiRiYWNrZHJvcD1udWxsfSxiYWNrZHJvcDpmdW5jdGlvbih0KXt2YXIgbj10aGlzLHI9dGhp
cy4kZWxlbWVudC5oYXNDbGFzcygiZmFkZSIpPyJmYWRlIjoiIjtpZih0aGlzLmlzU2hvd24mJnRoaXMu
b3B0aW9ucy5iYWNrZHJvcCl7dmFyIGk9ZS5zdXBwb3J0LnRyYW5zaXRpb24mJnI7dGhpcy4kYmFja2Ry
b3A9ZSgnPGRpdiBjbGFzcz0ibW9kYWwtYmFja2Ryb3AgJytyKyciIC8+JykuYXBwZW5kVG8oZG9jdW1l
bnQuYm9keSksdGhpcy4kYmFja2Ryb3AuY2xpY2sodGhpcy5vcHRpb25zLmJhY2tkcm9wPT0ic3RhdGlj
Ij9lLnByb3h5KHRoaXMuJGVsZW1lbnRbMF0uZm9jdXMsdGhpcy4kZWxlbWVudFswXSk6ZS5wcm94eSh0
aGlzLmhpZGUsdGhpcykpLGkmJnRoaXMuJGJhY2tkcm9wWzBdLm9mZnNldFdpZHRoLHRoaXMuJGJhY2tk
cm9wLmFkZENsYXNzKCJpbiIpO2lmKCF0KXJldHVybjtpP3RoaXMuJGJhY2tkcm9wLm9uZShlLnN1cHBv
cnQudHJhbnNpdGlvbi5lbmQsdCk6dCgpfWVsc2UhdGhpcy5pc1Nob3duJiZ0aGlzLiRiYWNrZHJvcD8o
dGhpcy4kYmFja2Ryb3AucmVtb3ZlQ2xhc3MoImluIiksZS5zdXBwb3J0LnRyYW5zaXRpb24mJnRoaXMu
JGVsZW1lbnQuaGFzQ2xhc3MoImZhZGUiKT90aGlzLiRiYWNrZHJvcC5vbmUoZS5zdXBwb3J0LnRyYW5z
aXRpb24uZW5kLHQpOnQoKSk6dCYmdCgpfX07dmFyIG49ZS5mbi5tb2RhbDtlLmZuLm1vZGFsPWZ1bmN0
aW9uKG4pe3JldHVybiB0aGlzLmVhY2goZnVuY3Rpb24oKXt2YXIgcj1lKHRoaXMpLGk9ci5kYXRhKCJt
b2RhbCIpLHM9ZS5leHRlbmQoe30sZS5mbi5tb2RhbC5kZWZhdWx0cyxyLmRhdGEoKSx0eXBlb2Ygbj09
Im9iamVjdCImJm4pO2l8fHIuZGF0YSgibW9kYWwiLGk9bmV3IHQodGhpcyxzKSksdHlwZW9mIG49PSJz
dHJpbmciP2lbbl0oKTpzLnNob3cmJmkuc2hvdygpfSl9LGUuZm4ubW9kYWwuZGVmYXVsdHM9e2JhY2tk
cm9wOiEwLGtleWJvYXJkOiEwLHNob3c6ITB9LGUuZm4ubW9kYWwuQ29uc3RydWN0b3I9dCxlLmZuLm1v
ZGFsLm5vQ29uZmxpY3Q9ZnVuY3Rpb24oKXtyZXR1cm4gZS5mbi5tb2RhbD1uLHRoaXN9LGUoZG9jdW1l
bnQpLm9uKCJjbGljay5tb2RhbC5kYXRhLWFwaSIsJ1tkYXRhLXRvZ2dsZT0ibW9kYWwiXScsZnVuY3Rp
b24odCl7dmFyIG49ZSh0aGlzKSxyPW4uYXR0cigiaHJlZiIpLGk9ZShuLmF0dHIoImRhdGEtdGFyZ2V0
Iil8fHImJnIucmVwbGFjZSgvLiooPz0jW15cc10rJCkvLCIiKSkscz1pLmRhdGEoIm1vZGFsIik/InRv
Z2dsZSI6ZS5leHRlbmQoe3JlbW90ZTohLyMvLnRlc3QocikmJnJ9LGkuZGF0YSgpLG4uZGF0YSgpKTt0
LnByZXZlbnREZWZhdWx0KCksaS5tb2RhbChzKS5vbmUoImhpZGUiLGZ1bmN0aW9uKCl7bi5mb2N1cygp
fSl9KX0od2luZG93LmpRdWVyeSksIWZ1bmN0aW9uKGUpeyJ1c2Ugc3RyaWN0Ijt2YXIgdD1mdW5jdGlv
bihlLHQpe3RoaXMuaW5pdCgidG9vbHRpcCIsZSx0KX07dC5wcm90b3R5cGU9e2NvbnN0cnVjdG9yOnQs
aW5pdDpmdW5jdGlvbih0LG4scil7dmFyIGkscyxvLHUsYTt0aGlzLnR5cGU9dCx0aGlzLiRlbGVtZW50
PWUobiksdGhpcy5vcHRpb25zPXRoaXMuZ2V0T3B0aW9ucyhyKSx0aGlzLmVuYWJsZWQ9ITAsbz10aGlz
Lm9wdGlvbnMudHJpZ2dlci5zcGxpdCgiICIpO2ZvcihhPW8ubGVuZ3RoO2EtLTspdT1vW2FdLHU9PSJj
bGljayI/dGhpcy4kZWxlbWVudC5vbigiY2xpY2suIit0aGlzLnR5cGUsdGhpcy5vcHRpb25zLnNlbGVj
dG9yLGUucHJveHkodGhpcy50b2dnbGUsdGhpcykpOnUhPSJtYW51YWwiJiYoaT11PT0iaG92ZXIiPyJt
b3VzZWVudGVyIjoiZm9jdXMiLHM9dT09ImhvdmVyIj8ibW91c2VsZWF2ZSI6ImJsdXIiLHRoaXMuJGVs
ZW1lbnQub24oaSsiLiIrdGhpcy50eXBlLHRoaXMub3B0aW9ucy5zZWxlY3RvcixlLnByb3h5KHRoaXMu
ZW50ZXIsdGhpcykpLHRoaXMuJGVsZW1lbnQub24ocysiLiIrdGhpcy50eXBlLHRoaXMub3B0aW9ucy5z
ZWxlY3RvcixlLnByb3h5KHRoaXMubGVhdmUsdGhpcykpKTt0aGlzLm9wdGlvbnMuc2VsZWN0b3I/dGhp
cy5fb3B0aW9ucz1lLmV4dGVuZCh7fSx0aGlzLm9wdGlvbnMse3RyaWdnZXI6Im1hbnVhbCIsc2VsZWN0
b3I6IiJ9KTp0aGlzLmZpeFRpdGxlKCl9LGdldE9wdGlvbnM6ZnVuY3Rpb24odCl7cmV0dXJuIHQ9ZS5l
eHRlbmQoe30sZS5mblt0aGlzLnR5cGVdLmRlZmF1bHRzLHRoaXMuJGVsZW1lbnQuZGF0YSgpLHQpLHQu
ZGVsYXkmJnR5cGVvZiB0LmRlbGF5PT0ibnVtYmVyIiYmKHQuZGVsYXk9e3Nob3c6dC5kZWxheSxoaWRl
OnQuZGVsYXl9KSx0fSxlbnRlcjpmdW5jdGlvbih0KXt2YXIgbj1lKHQuY3VycmVudFRhcmdldClbdGhp
cy50eXBlXSh0aGlzLl9vcHRpb25zKS5kYXRhKHRoaXMudHlwZSk7aWYoIW4ub3B0aW9ucy5kZWxheXx8
IW4ub3B0aW9ucy5kZWxheS5zaG93KXJldHVybiBuLnNob3coKTtjbGVhclRpbWVvdXQodGhpcy50aW1l
b3V0KSxuLmhvdmVyU3RhdGU9ImluIix0aGlzLnRpbWVvdXQ9c2V0VGltZW91dChmdW5jdGlvbigpe24u
aG92ZXJTdGF0ZT09ImluIiYmbi5zaG93KCl9LG4ub3B0aW9ucy5kZWxheS5zaG93KX0sbGVhdmU6ZnVu
Y3Rpb24odCl7dmFyIG49ZSh0LmN1cnJlbnRUYXJnZXQpW3RoaXMudHlwZV0odGhpcy5fb3B0aW9ucyku
ZGF0YSh0aGlzLnR5cGUpO3RoaXMudGltZW91dCYmY2xlYXJUaW1lb3V0KHRoaXMudGltZW91dCk7aWYo
IW4ub3B0aW9ucy5kZWxheXx8IW4ub3B0aW9ucy5kZWxheS5oaWRlKXJldHVybiBuLmhpZGUoKTtuLmhv
dmVyU3RhdGU9Im91dCIsdGhpcy50aW1lb3V0PXNldFRpbWVvdXQoZnVuY3Rpb24oKXtuLmhvdmVyU3Rh
dGU9PSJvdXQiJiZuLmhpZGUoKX0sbi5vcHRpb25zLmRlbGF5LmhpZGUpfSxzaG93OmZ1bmN0aW9uKCl7
dmFyIHQsbixyLGkscyxvLHU9ZS5FdmVudCgic2hvdyIpO2lmKHRoaXMuaGFzQ29udGVudCgpJiZ0aGlz
LmVuYWJsZWQpe3RoaXMuJGVsZW1lbnQudHJpZ2dlcih1KTtpZih1LmlzRGVmYXVsdFByZXZlbnRlZCgp
KXJldHVybjt0PXRoaXMudGlwKCksdGhpcy5zZXRDb250ZW50KCksdGhpcy5vcHRpb25zLmFuaW1hdGlv
biYmdC5hZGRDbGFzcygiZmFkZSIpLHM9dHlwZW9mIHRoaXMub3B0aW9ucy5wbGFjZW1lbnQ9PSJmdW5j
dGlvbiI/dGhpcy5vcHRpb25zLnBsYWNlbWVudC5jYWxsKHRoaXMsdFswXSx0aGlzLiRlbGVtZW50WzBd
KTp0aGlzLm9wdGlvbnMucGxhY2VtZW50LHQuZGV0YWNoKCkuY3NzKHt0b3A6MCxsZWZ0OjAsZGlzcGxh
eToiYmxvY2sifSksdGhpcy5vcHRpb25zLmNvbnRhaW5lcj90LmFwcGVuZFRvKHRoaXMub3B0aW9ucy5j
b250YWluZXIpOnQuaW5zZXJ0QWZ0ZXIodGhpcy4kZWxlbWVudCksbj10aGlzLmdldFBvc2l0aW9uKCks
cj10WzBdLm9mZnNldFdpZHRoLGk9dFswXS5vZmZzZXRIZWlnaHQ7c3dpdGNoKHMpe2Nhc2UiYm90dG9t
IjpvPXt0b3A6bi50b3Arbi5oZWlnaHQsbGVmdDpuLmxlZnQrbi53aWR0aC8yLXIvMn07YnJlYWs7Y2Fz
ZSJ0b3AiOm89e3RvcDpuLnRvcC1pLGxlZnQ6bi5sZWZ0K24ud2lkdGgvMi1yLzJ9O2JyZWFrO2Nhc2Ui
bGVmdCI6bz17dG9wOm4udG9wK24uaGVpZ2h0LzItaS8yLGxlZnQ6bi5sZWZ0LXJ9O2JyZWFrO2Nhc2Ui
cmlnaHQiOm89e3RvcDpuLnRvcCtuLmhlaWdodC8yLWkvMixsZWZ0Om4ubGVmdCtuLndpZHRofX10aGlz
LmFwcGx5UGxhY2VtZW50KG8scyksdGhpcy4kZWxlbWVudC50cmlnZ2VyKCJzaG93biIpfX0sYXBwbHlQ
bGFjZW1lbnQ6ZnVuY3Rpb24oZSx0KXt2YXIgbj10aGlzLnRpcCgpLHI9blswXS5vZmZzZXRXaWR0aCxp
PW5bMF0ub2Zmc2V0SGVpZ2h0LHMsbyx1LGE7bi5vZmZzZXQoZSkuYWRkQ2xhc3ModCkuYWRkQ2xhc3Mo
ImluIikscz1uWzBdLm9mZnNldFdpZHRoLG89blswXS5vZmZzZXRIZWlnaHQsdD09InRvcCImJm8hPWkm
JihlLnRvcD1lLnRvcCtpLW8sYT0hMCksdD09ImJvdHRvbSJ8fHQ9PSJ0b3AiPyh1PTAsZS5sZWZ0PDAm
Jih1PWUubGVmdCotMixlLmxlZnQ9MCxuLm9mZnNldChlKSxzPW5bMF0ub2Zmc2V0V2lkdGgsbz1uWzBd
Lm9mZnNldEhlaWdodCksdGhpcy5yZXBsYWNlQXJyb3codS1yK3MscywibGVmdCIpKTp0aGlzLnJlcGxh
Y2VBcnJvdyhvLWksbywidG9wIiksYSYmbi5vZmZzZXQoZSl9LHJlcGxhY2VBcnJvdzpmdW5jdGlvbihl
LHQsbil7dGhpcy5hcnJvdygpLmNzcyhuLGU/NTAqKDEtZS90KSsiJSI6IiIpfSxzZXRDb250ZW50OmZ1
bmN0aW9uKCl7dmFyIGU9dGhpcy50aXAoKSx0PXRoaXMuZ2V0VGl0bGUoKTtlLmZpbmQoIi50b29sdGlw
LWlubmVyIilbdGhpcy5vcHRpb25zLmh0bWw/Imh0bWwiOiJ0ZXh0Il0odCksZS5yZW1vdmVDbGFzcygi
ZmFkZSBpbiB0b3AgYm90dG9tIGxlZnQgcmlnaHQiKX0saGlkZTpmdW5jdGlvbigpe2Z1bmN0aW9uIGko
KXt2YXIgdD1zZXRUaW1lb3V0KGZ1bmN0aW9uKCl7bi5vZmYoZS5zdXBwb3J0LnRyYW5zaXRpb24uZW5k
KS5kZXRhY2goKX0sNTAwKTtuLm9uZShlLnN1cHBvcnQudHJhbnNpdGlvbi5lbmQsZnVuY3Rpb24oKXtj
bGVhclRpbWVvdXQodCksbi5kZXRhY2goKX0pfXZhciB0PXRoaXMsbj10aGlzLnRpcCgpLHI9ZS5FdmVu
dCgiaGlkZSIpO3RoaXMuJGVsZW1lbnQudHJpZ2dlcihyKTtpZihyLmlzRGVmYXVsdFByZXZlbnRlZCgp
KXJldHVybjtyZXR1cm4gbi5yZW1vdmVDbGFzcygiaW4iKSxlLnN1cHBvcnQudHJhbnNpdGlvbiYmdGhp
cy4kdGlwLmhhc0NsYXNzKCJmYWRlIik/aSgpOm4uZGV0YWNoKCksdGhpcy4kZWxlbWVudC50cmlnZ2Vy
KCJoaWRkZW4iKSx0aGlzfSxmaXhUaXRsZTpmdW5jdGlvbigpe3ZhciBlPXRoaXMuJGVsZW1lbnQ7KGUu
YXR0cigidGl0bGUiKXx8dHlwZW9mIGUuYXR0cigiZGF0YS1vcmlnaW5hbC10aXRsZSIpIT0ic3RyaW5n
IikmJmUuYXR0cigiZGF0YS1vcmlnaW5hbC10aXRsZSIsZS5hdHRyKCJ0aXRsZSIpfHwiIikuYXR0cigi
dGl0bGUiLCIiKX0saGFzQ29udGVudDpmdW5jdGlvbigpe3JldHVybiB0aGlzLmdldFRpdGxlKCl9LGdl
dFBvc2l0aW9uOmZ1bmN0aW9uKCl7dmFyIHQ9dGhpcy4kZWxlbWVudFswXTtyZXR1cm4gZS5leHRlbmQo
e30sdHlwZW9mIHQuZ2V0Qm91bmRpbmdDbGllbnRSZWN0PT0iZnVuY3Rpb24iP3QuZ2V0Qm91bmRpbmdD
bGllbnRSZWN0KCk6e3dpZHRoOnQub2Zmc2V0V2lkdGgsaGVpZ2h0OnQub2Zmc2V0SGVpZ2h0fSx0aGlz
LiRlbGVtZW50Lm9mZnNldCgpKX0sZ2V0VGl0bGU6ZnVuY3Rpb24oKXt2YXIgZSx0PXRoaXMuJGVsZW1l
bnQsbj10aGlzLm9wdGlvbnM7cmV0dXJuIGU9dC5hdHRyKCJkYXRhLW9yaWdpbmFsLXRpdGxlIil8fCh0
eXBlb2Ygbi50aXRsZT09ImZ1bmN0aW9uIj9uLnRpdGxlLmNhbGwodFswXSk6bi50aXRsZSksZX0sdGlw
OmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuJHRpcD10aGlzLiR0aXB8fGUodGhpcy5vcHRpb25zLnRlbXBs
YXRlKX0sYXJyb3c6ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy4kYXJyb3c9dGhpcy4kYXJyb3d8fHRoaXMu
dGlwKCkuZmluZCgiLnRvb2x0aXAtYXJyb3ciKX0sdmFsaWRhdGU6ZnVuY3Rpb24oKXt0aGlzLiRlbGVt
ZW50WzBdLnBhcmVudE5vZGV8fCh0aGlzLmhpZGUoKSx0aGlzLiRlbGVtZW50PW51bGwsdGhpcy5vcHRp
b25zPW51bGwpfSxlbmFibGU6ZnVuY3Rpb24oKXt0aGlzLmVuYWJsZWQ9ITB9LGRpc2FibGU6ZnVuY3Rp
b24oKXt0aGlzLmVuYWJsZWQ9ITF9LHRvZ2dsZUVuYWJsZWQ6ZnVuY3Rpb24oKXt0aGlzLmVuYWJsZWQ9
IXRoaXMuZW5hYmxlZH0sdG9nZ2xlOmZ1bmN0aW9uKHQpe3ZhciBuPXQ/ZSh0LmN1cnJlbnRUYXJnZXQp
W3RoaXMudHlwZV0odGhpcy5fb3B0aW9ucykuZGF0YSh0aGlzLnR5cGUpOnRoaXM7bi50aXAoKS5oYXND
bGFzcygiaW4iKT9uLmhpZGUoKTpuLnNob3coKX0sZGVzdHJveTpmdW5jdGlvbigpe3RoaXMuaGlkZSgp
LiRlbGVtZW50Lm9mZigiLiIrdGhpcy50eXBlKS5yZW1vdmVEYXRhKHRoaXMudHlwZSl9fTt2YXIgbj1l
LmZuLnRvb2x0aXA7ZS5mbi50b29sdGlwPWZ1bmN0aW9uKG4pe3JldHVybiB0aGlzLmVhY2goZnVuY3Rp
b24oKXt2YXIgcj1lKHRoaXMpLGk9ci5kYXRhKCJ0b29sdGlwIikscz10eXBlb2Ygbj09Im9iamVjdCIm
Jm47aXx8ci5kYXRhKCJ0b29sdGlwIixpPW5ldyB0KHRoaXMscykpLHR5cGVvZiBuPT0ic3RyaW5nIiYm
aVtuXSgpfSl9LGUuZm4udG9vbHRpcC5Db25zdHJ1Y3Rvcj10LGUuZm4udG9vbHRpcC5kZWZhdWx0cz17
YW5pbWF0aW9uOiEwLHBsYWNlbWVudDoidG9wIixzZWxlY3RvcjohMSx0ZW1wbGF0ZTonPGRpdiBjbGFz
cz0idG9vbHRpcCI+PGRpdiBjbGFzcz0idG9vbHRpcC1hcnJvdyI+PC9kaXY+PGRpdiBjbGFzcz0idG9v
bHRpcC1pbm5lciI+PC9kaXY+PC9kaXY+Jyx0cmlnZ2VyOiJob3ZlciBmb2N1cyIsdGl0bGU6IiIsZGVs
YXk6MCxodG1sOiExLGNvbnRhaW5lcjohMX0sZS5mbi50b29sdGlwLm5vQ29uZmxpY3Q9ZnVuY3Rpb24o
KXtyZXR1cm4gZS5mbi50b29sdGlwPW4sdGhpc319KHdpbmRvdy5qUXVlcnkpLCFmdW5jdGlvbihlKXsi
dXNlIHN0cmljdCI7dmFyIHQ9ZnVuY3Rpb24oZSx0KXt0aGlzLmluaXQoInBvcG92ZXIiLGUsdCl9O3Qu
cHJvdG90eXBlPWUuZXh0ZW5kKHt9LGUuZm4udG9vbHRpcC5Db25zdHJ1Y3Rvci5wcm90b3R5cGUse2Nv
bnN0cnVjdG9yOnQsc2V0Q29udGVudDpmdW5jdGlvbigpe3ZhciBlPXRoaXMudGlwKCksdD10aGlzLmdl
dFRpdGxlKCksbj10aGlzLmdldENvbnRlbnQoKTtlLmZpbmQoIi5wb3BvdmVyLXRpdGxlIilbdGhpcy5v
cHRpb25zLmh0bWw/Imh0bWwiOiJ0ZXh0Il0odCksZS5maW5kKCIucG9wb3Zlci1jb250ZW50IilbdGhp
cy5vcHRpb25zLmh0bWw/Imh0bWwiOiJ0ZXh0Il0obiksZS5yZW1vdmVDbGFzcygiZmFkZSB0b3AgYm90
dG9tIGxlZnQgcmlnaHQgaW4iKX0saGFzQ29udGVudDpmdW5jdGlvbigpe3JldHVybiB0aGlzLmdldFRp
dGxlKCl8fHRoaXMuZ2V0Q29udGVudCgpfSxnZXRDb250ZW50OmZ1bmN0aW9uKCl7dmFyIGUsdD10aGlz
LiRlbGVtZW50LG49dGhpcy5vcHRpb25zO3JldHVybiBlPSh0eXBlb2Ygbi5jb250ZW50PT0iZnVuY3Rp
b24iP24uY29udGVudC5jYWxsKHRbMF0pOm4uY29udGVudCl8fHQuYXR0cigiZGF0YS1jb250ZW50Iiks
ZX0sdGlwOmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuJHRpcHx8KHRoaXMuJHRpcD1lKHRoaXMub3B0aW9u
cy50ZW1wbGF0ZSkpLHRoaXMuJHRpcH0sZGVzdHJveTpmdW5jdGlvbigpe3RoaXMuaGlkZSgpLiRlbGVt
ZW50Lm9mZigiLiIrdGhpcy50eXBlKS5yZW1vdmVEYXRhKHRoaXMudHlwZSl9fSk7dmFyIG49ZS5mbi5w
b3BvdmVyO2UuZm4ucG9wb3Zlcj1mdW5jdGlvbihuKXtyZXR1cm4gdGhpcy5lYWNoKGZ1bmN0aW9uKCl7
dmFyIHI9ZSh0aGlzKSxpPXIuZGF0YSgicG9wb3ZlciIpLHM9dHlwZW9mIG49PSJvYmplY3QiJiZuO2l8
fHIuZGF0YSgicG9wb3ZlciIsaT1uZXcgdCh0aGlzLHMpKSx0eXBlb2Ygbj09InN0cmluZyImJmlbbl0o
KX0pfSxlLmZuLnBvcG92ZXIuQ29uc3RydWN0b3I9dCxlLmZuLnBvcG92ZXIuZGVmYXVsdHM9ZS5leHRl
bmQoe30sZS5mbi50b29sdGlwLmRlZmF1bHRzLHtwbGFjZW1lbnQ6InJpZ2h0Iix0cmlnZ2VyOiJjbGlj
ayIsY29udGVudDoiIix0ZW1wbGF0ZTonPGRpdiBjbGFzcz0icG9wb3ZlciI+PGRpdiBjbGFzcz0iYXJy
b3ciPjwvZGl2PjxoMyBjbGFzcz0icG9wb3Zlci10aXRsZSI+PC9oMz48ZGl2IGNsYXNzPSJwb3BvdmVy
LWNvbnRlbnQiPjwvZGl2PjwvZGl2Pid9KSxlLmZuLnBvcG92ZXIubm9Db25mbGljdD1mdW5jdGlvbigp
e3JldHVybiBlLmZuLnBvcG92ZXI9bix0aGlzfX0od2luZG93LmpRdWVyeSksIWZ1bmN0aW9uKGUpeyJ1
c2Ugc3RyaWN0IjtmdW5jdGlvbiB0KHQsbil7dmFyIHI9ZS5wcm94eSh0aGlzLnByb2Nlc3MsdGhpcyks
aT1lKHQpLmlzKCJib2R5Iik/ZSh3aW5kb3cpOmUodCksczt0aGlzLm9wdGlvbnM9ZS5leHRlbmQoe30s
ZS5mbi5zY3JvbGxzcHkuZGVmYXVsdHMsbiksdGhpcy4kc2Nyb2xsRWxlbWVudD1pLm9uKCJzY3JvbGwu
c2Nyb2xsLXNweS5kYXRhLWFwaSIsciksdGhpcy5zZWxlY3Rvcj0odGhpcy5vcHRpb25zLnRhcmdldHx8
KHM9ZSh0KS5hdHRyKCJocmVmIikpJiZzLnJlcGxhY2UoLy4qKD89I1teXHNdKyQpLywiIil8fCIiKSsi
IC5uYXYgbGkgPiBhIix0aGlzLiRib2R5PWUoImJvZHkiKSx0aGlzLnJlZnJlc2goKSx0aGlzLnByb2Nl
c3MoKX10LnByb3RvdHlwZT17Y29uc3RydWN0b3I6dCxyZWZyZXNoOmZ1bmN0aW9uKCl7dmFyIHQ9dGhp
cyxuO3RoaXMub2Zmc2V0cz1lKFtdKSx0aGlzLnRhcmdldHM9ZShbXSksbj10aGlzLiRib2R5LmZpbmQo
dGhpcy5zZWxlY3RvcikubWFwKGZ1bmN0aW9uKCl7dmFyIG49ZSh0aGlzKSxyPW4uZGF0YSgidGFyZ2V0
Iil8fG4uYXR0cigiaHJlZiIpLGk9L14jXHcvLnRlc3QocikmJmUocik7cmV0dXJuIGkmJmkubGVuZ3Ro
JiZbW2kucG9zaXRpb24oKS50b3ArKCFlLmlzV2luZG93KHQuJHNjcm9sbEVsZW1lbnQuZ2V0KDApKSYm
dC4kc2Nyb2xsRWxlbWVudC5zY3JvbGxUb3AoKSkscl1dfHxudWxsfSkuc29ydChmdW5jdGlvbihlLHQp
e3JldHVybiBlWzBdLXRbMF19KS5lYWNoKGZ1bmN0aW9uKCl7dC5vZmZzZXRzLnB1c2godGhpc1swXSks
dC50YXJnZXRzLnB1c2godGhpc1sxXSl9KX0scHJvY2VzczpmdW5jdGlvbigpe3ZhciBlPXRoaXMuJHNj
cm9sbEVsZW1lbnQuc2Nyb2xsVG9wKCkrdGhpcy5vcHRpb25zLm9mZnNldCx0PXRoaXMuJHNjcm9sbEVs
ZW1lbnRbMF0uc2Nyb2xsSGVpZ2h0fHx0aGlzLiRib2R5WzBdLnNjcm9sbEhlaWdodCxuPXQtdGhpcy4k
c2Nyb2xsRWxlbWVudC5oZWlnaHQoKSxyPXRoaXMub2Zmc2V0cyxpPXRoaXMudGFyZ2V0cyxzPXRoaXMu
YWN0aXZlVGFyZ2V0LG87aWYoZT49bilyZXR1cm4gcyE9KG89aS5sYXN0KClbMF0pJiZ0aGlzLmFjdGl2
YXRlKG8pO2ZvcihvPXIubGVuZ3RoO28tLTspcyE9aVtvXSYmZT49cltvXSYmKCFyW28rMV18fGU8PXJb
bysxXSkmJnRoaXMuYWN0aXZhdGUoaVtvXSl9LGFjdGl2YXRlOmZ1bmN0aW9uKHQpe3ZhciBuLHI7dGhp
cy5hY3RpdmVUYXJnZXQ9dCxlKHRoaXMuc2VsZWN0b3IpLnBhcmVudCgiLmFjdGl2ZSIpLnJlbW92ZUNs
YXNzKCJhY3RpdmUiKSxyPXRoaXMuc2VsZWN0b3IrJ1tkYXRhLXRhcmdldD0iJyt0KyciXSwnK3RoaXMu
c2VsZWN0b3IrJ1tocmVmPSInK3QrJyJdJyxuPWUocikucGFyZW50KCJsaSIpLmFkZENsYXNzKCJhY3Rp
dmUiKSxuLnBhcmVudCgiLmRyb3Bkb3duLW1lbnUiKS5sZW5ndGgmJihuPW4uY2xvc2VzdCgibGkuZHJv
cGRvd24iKS5hZGRDbGFzcygiYWN0aXZlIikpLG4udHJpZ2dlcigiYWN0aXZhdGUiKX19O3ZhciBuPWUu
Zm4uc2Nyb2xsc3B5O2UuZm4uc2Nyb2xsc3B5PWZ1bmN0aW9uKG4pe3JldHVybiB0aGlzLmVhY2goZnVu
Y3Rpb24oKXt2YXIgcj1lKHRoaXMpLGk9ci5kYXRhKCJzY3JvbGxzcHkiKSxzPXR5cGVvZiBuPT0ib2Jq
ZWN0IiYmbjtpfHxyLmRhdGEoInNjcm9sbHNweSIsaT1uZXcgdCh0aGlzLHMpKSx0eXBlb2Ygbj09InN0
cmluZyImJmlbbl0oKX0pfSxlLmZuLnNjcm9sbHNweS5Db25zdHJ1Y3Rvcj10LGUuZm4uc2Nyb2xsc3B5
LmRlZmF1bHRzPXtvZmZzZXQ6MTB9LGUuZm4uc2Nyb2xsc3B5Lm5vQ29uZmxpY3Q9ZnVuY3Rpb24oKXty
ZXR1cm4gZS5mbi5zY3JvbGxzcHk9bix0aGlzfSxlKHdpbmRvdykub24oImxvYWQiLGZ1bmN0aW9uKCl7
ZSgnW2RhdGEtc3B5PSJzY3JvbGwiXScpLmVhY2goZnVuY3Rpb24oKXt2YXIgdD1lKHRoaXMpO3Quc2Ny
b2xsc3B5KHQuZGF0YSgpKX0pfSl9KHdpbmRvdy5qUXVlcnkpLCFmdW5jdGlvbihlKXsidXNlIHN0cmlj
dCI7dmFyIHQ9ZnVuY3Rpb24odCl7dGhpcy5lbGVtZW50PWUodCl9O3QucHJvdG90eXBlPXtjb25zdHJ1
Y3Rvcjp0LHNob3c6ZnVuY3Rpb24oKXt2YXIgdD10aGlzLmVsZW1lbnQsbj10LmNsb3Nlc3QoInVsOm5v
dCguZHJvcGRvd24tbWVudSkiKSxyPXQuYXR0cigiZGF0YS10YXJnZXQiKSxpLHMsbztyfHwocj10LmF0
dHIoImhyZWYiKSxyPXImJnIucmVwbGFjZSgvLiooPz0jW15cc10qJCkvLCIiKSk7aWYodC5wYXJlbnQo
ImxpIikuaGFzQ2xhc3MoImFjdGl2ZSIpKXJldHVybjtpPW4uZmluZCgiLmFjdGl2ZTpsYXN0IGEiKVsw
XSxvPWUuRXZlbnQoInNob3ciLHtyZWxhdGVkVGFyZ2V0Oml9KSx0LnRyaWdnZXIobyk7aWYoby5pc0Rl
ZmF1bHRQcmV2ZW50ZWQoKSlyZXR1cm47cz1lKHIpLHRoaXMuYWN0aXZhdGUodC5wYXJlbnQoImxpIiks
biksdGhpcy5hY3RpdmF0ZShzLHMucGFyZW50KCksZnVuY3Rpb24oKXt0LnRyaWdnZXIoe3R5cGU6InNo
b3duIixyZWxhdGVkVGFyZ2V0Oml9KX0pfSxhY3RpdmF0ZTpmdW5jdGlvbih0LG4scil7ZnVuY3Rpb24g
bygpe2kucmVtb3ZlQ2xhc3MoImFjdGl2ZSIpLmZpbmQoIj4gLmRyb3Bkb3duLW1lbnUgPiAuYWN0aXZl
IikucmVtb3ZlQ2xhc3MoImFjdGl2ZSIpLHQuYWRkQ2xhc3MoImFjdGl2ZSIpLHM/KHRbMF0ub2Zmc2V0
V2lkdGgsdC5hZGRDbGFzcygiaW4iKSk6dC5yZW1vdmVDbGFzcygiZmFkZSIpLHQucGFyZW50KCIuZHJv
cGRvd24tbWVudSIpJiZ0LmNsb3Nlc3QoImxpLmRyb3Bkb3duIikuYWRkQ2xhc3MoImFjdGl2ZSIpLHIm
JnIoKX12YXIgaT1uLmZpbmQoIj4gLmFjdGl2ZSIpLHM9ciYmZS5zdXBwb3J0LnRyYW5zaXRpb24mJmku
aGFzQ2xhc3MoImZhZGUiKTtzP2kub25lKGUuc3VwcG9ydC50cmFuc2l0aW9uLmVuZCxvKTpvKCksaS5y
ZW1vdmVDbGFzcygiaW4iKX19O3ZhciBuPWUuZm4udGFiO2UuZm4udGFiPWZ1bmN0aW9uKG4pe3JldHVy
biB0aGlzLmVhY2goZnVuY3Rpb24oKXt2YXIgcj1lKHRoaXMpLGk9ci5kYXRhKCJ0YWIiKTtpfHxyLmRh
dGEoInRhYiIsaT1uZXcgdCh0aGlzKSksdHlwZW9mIG49PSJzdHJpbmciJiZpW25dKCl9KX0sZS5mbi50
YWIuQ29uc3RydWN0b3I9dCxlLmZuLnRhYi5ub0NvbmZsaWN0PWZ1bmN0aW9uKCl7cmV0dXJuIGUuZm4u
dGFiPW4sdGhpc30sZShkb2N1bWVudCkub24oImNsaWNrLnRhYi5kYXRhLWFwaSIsJ1tkYXRhLXRvZ2ds
ZT0idGFiIl0sIFtkYXRhLXRvZ2dsZT0icGlsbCJdJyxmdW5jdGlvbih0KXt0LnByZXZlbnREZWZhdWx0
KCksZSh0aGlzKS50YWIoInNob3ciKX0pfSh3aW5kb3cualF1ZXJ5KSwhZnVuY3Rpb24oZSl7InVzZSBz
dHJpY3QiO3ZhciB0PWZ1bmN0aW9uKHQsbil7dGhpcy4kZWxlbWVudD1lKHQpLHRoaXMub3B0aW9ucz1l
LmV4dGVuZCh7fSxlLmZuLnR5cGVhaGVhZC5kZWZhdWx0cyxuKSx0aGlzLm1hdGNoZXI9dGhpcy5vcHRp
b25zLm1hdGNoZXJ8fHRoaXMubWF0Y2hlcix0aGlzLnNvcnRlcj10aGlzLm9wdGlvbnMuc29ydGVyfHx0
aGlzLnNvcnRlcix0aGlzLmhpZ2hsaWdodGVyPXRoaXMub3B0aW9ucy5oaWdobGlnaHRlcnx8dGhpcy5o
aWdobGlnaHRlcix0aGlzLnVwZGF0ZXI9dGhpcy5vcHRpb25zLnVwZGF0ZXJ8fHRoaXMudXBkYXRlcix0
aGlzLnNvdXJjZT10aGlzLm9wdGlvbnMuc291cmNlLHRoaXMuJG1lbnU9ZSh0aGlzLm9wdGlvbnMubWVu
dSksdGhpcy5zaG93bj0hMSx0aGlzLmxpc3RlbigpfTt0LnByb3RvdHlwZT17Y29uc3RydWN0b3I6dCxz
ZWxlY3Q6ZnVuY3Rpb24oKXt2YXIgZT10aGlzLiRtZW51LmZpbmQoIi5hY3RpdmUiKS5hdHRyKCJkYXRh
LXZhbHVlIik7cmV0dXJuIHRoaXMuJGVsZW1lbnQudmFsKHRoaXMudXBkYXRlcihlKSkuY2hhbmdlKCks
dGhpcy5oaWRlKCl9LHVwZGF0ZXI6ZnVuY3Rpb24oZSl7cmV0dXJuIGV9LHNob3c6ZnVuY3Rpb24oKXt2
YXIgdD1lLmV4dGVuZCh7fSx0aGlzLiRlbGVtZW50LnBvc2l0aW9uKCkse2hlaWdodDp0aGlzLiRlbGVt
ZW50WzBdLm9mZnNldEhlaWdodH0pO3JldHVybiB0aGlzLiRtZW51Lmluc2VydEFmdGVyKHRoaXMuJGVs
ZW1lbnQpLmNzcyh7dG9wOnQudG9wK3QuaGVpZ2h0LGxlZnQ6dC5sZWZ0fSkuc2hvdygpLHRoaXMuc2hv
d249ITAsdGhpc30saGlkZTpmdW5jdGlvbigpe3JldHVybiB0aGlzLiRtZW51LmhpZGUoKSx0aGlzLnNo
b3duPSExLHRoaXN9LGxvb2t1cDpmdW5jdGlvbih0KXt2YXIgbjtyZXR1cm4gdGhpcy5xdWVyeT10aGlz
LiRlbGVtZW50LnZhbCgpLCF0aGlzLnF1ZXJ5fHx0aGlzLnF1ZXJ5Lmxlbmd0aDx0aGlzLm9wdGlvbnMu
bWluTGVuZ3RoP3RoaXMuc2hvd24/dGhpcy5oaWRlKCk6dGhpczoobj1lLmlzRnVuY3Rpb24odGhpcy5z
b3VyY2UpP3RoaXMuc291cmNlKHRoaXMucXVlcnksZS5wcm94eSh0aGlzLnByb2Nlc3MsdGhpcykpOnRo
aXMuc291cmNlLG4/dGhpcy5wcm9jZXNzKG4pOnRoaXMpfSxwcm9jZXNzOmZ1bmN0aW9uKHQpe3ZhciBu
PXRoaXM7cmV0dXJuIHQ9ZS5ncmVwKHQsZnVuY3Rpb24oZSl7cmV0dXJuIG4ubWF0Y2hlcihlKX0pLHQ9
dGhpcy5zb3J0ZXIodCksdC5sZW5ndGg/dGhpcy5yZW5kZXIodC5zbGljZSgwLHRoaXMub3B0aW9ucy5p
dGVtcykpLnNob3coKTp0aGlzLnNob3duP3RoaXMuaGlkZSgpOnRoaXN9LG1hdGNoZXI6ZnVuY3Rpb24o
ZSl7cmV0dXJufmUudG9Mb3dlckNhc2UoKS5pbmRleE9mKHRoaXMucXVlcnkudG9Mb3dlckNhc2UoKSl9
LHNvcnRlcjpmdW5jdGlvbihlKXt2YXIgdD1bXSxuPVtdLHI9W10saTt3aGlsZShpPWUuc2hpZnQoKSlp
LnRvTG93ZXJDYXNlKCkuaW5kZXhPZih0aGlzLnF1ZXJ5LnRvTG93ZXJDYXNlKCkpP35pLmluZGV4T2Yo
dGhpcy5xdWVyeSk/bi5wdXNoKGkpOnIucHVzaChpKTp0LnB1c2goaSk7cmV0dXJuIHQuY29uY2F0KG4s
cil9LGhpZ2hsaWdodGVyOmZ1bmN0aW9uKGUpe3ZhciB0PXRoaXMucXVlcnkucmVwbGFjZSgvW1wtXFtc
XXt9KCkqKz8uLFxcXF4kfCNcc10vZywiXFwkJiIpO3JldHVybiBlLnJlcGxhY2UobmV3IFJlZ0V4cCgi
KCIrdCsiKSIsImlnIiksZnVuY3Rpb24oZSx0KXtyZXR1cm4iPHN0cm9uZz4iK3QrIjwvc3Ryb25nPiJ9
KX0scmVuZGVyOmZ1bmN0aW9uKHQpe3ZhciBuPXRoaXM7cmV0dXJuIHQ9ZSh0KS5tYXAoZnVuY3Rpb24o
dCxyKXtyZXR1cm4gdD1lKG4ub3B0aW9ucy5pdGVtKS5hdHRyKCJkYXRhLXZhbHVlIixyKSx0LmZpbmQo
ImEiKS5odG1sKG4uaGlnaGxpZ2h0ZXIocikpLHRbMF19KSx0LmZpcnN0KCkuYWRkQ2xhc3MoImFjdGl2
ZSIpLHRoaXMuJG1lbnUuaHRtbCh0KSx0aGlzfSxuZXh0OmZ1bmN0aW9uKHQpe3ZhciBuPXRoaXMuJG1l
bnUuZmluZCgiLmFjdGl2ZSIpLnJlbW92ZUNsYXNzKCJhY3RpdmUiKSxyPW4ubmV4dCgpO3IubGVuZ3Ro
fHwocj1lKHRoaXMuJG1lbnUuZmluZCgibGkiKVswXSkpLHIuYWRkQ2xhc3MoImFjdGl2ZSIpfSxwcmV2
OmZ1bmN0aW9uKGUpe3ZhciB0PXRoaXMuJG1lbnUuZmluZCgiLmFjdGl2ZSIpLnJlbW92ZUNsYXNzKCJh
Y3RpdmUiKSxuPXQucHJldigpO24ubGVuZ3RofHwobj10aGlzLiRtZW51LmZpbmQoImxpIikubGFzdCgp
KSxuLmFkZENsYXNzKCJhY3RpdmUiKX0sbGlzdGVuOmZ1bmN0aW9uKCl7dGhpcy4kZWxlbWVudC5vbigi
Zm9jdXMiLGUucHJveHkodGhpcy5mb2N1cyx0aGlzKSkub24oImJsdXIiLGUucHJveHkodGhpcy5ibHVy
LHRoaXMpKS5vbigia2V5cHJlc3MiLGUucHJveHkodGhpcy5rZXlwcmVzcyx0aGlzKSkub24oImtleXVw
IixlLnByb3h5KHRoaXMua2V5dXAsdGhpcykpLHRoaXMuZXZlbnRTdXBwb3J0ZWQoImtleWRvd24iKSYm
dGhpcy4kZWxlbWVudC5vbigia2V5ZG93biIsZS5wcm94eSh0aGlzLmtleWRvd24sdGhpcykpLHRoaXMu
JG1lbnUub24oImNsaWNrIixlLnByb3h5KHRoaXMuY2xpY2ssdGhpcykpLm9uKCJtb3VzZWVudGVyIiwi
bGkiLGUucHJveHkodGhpcy5tb3VzZWVudGVyLHRoaXMpKS5vbigibW91c2VsZWF2ZSIsImxpIixlLnBy
b3h5KHRoaXMubW91c2VsZWF2ZSx0aGlzKSl9LGV2ZW50U3VwcG9ydGVkOmZ1bmN0aW9uKGUpe3ZhciB0
PWUgaW4gdGhpcy4kZWxlbWVudDtyZXR1cm4gdHx8KHRoaXMuJGVsZW1lbnQuc2V0QXR0cmlidXRlKGUs
InJldHVybjsiKSx0PXR5cGVvZiB0aGlzLiRlbGVtZW50W2VdPT0iZnVuY3Rpb24iKSx0fSxtb3ZlOmZ1
bmN0aW9uKGUpe2lmKCF0aGlzLnNob3duKXJldHVybjtzd2l0Y2goZS5rZXlDb2RlKXtjYXNlIDk6Y2Fz
ZSAxMzpjYXNlIDI3OmUucHJldmVudERlZmF1bHQoKTticmVhaztjYXNlIDM4OmUucHJldmVudERlZmF1
bHQoKSx0aGlzLnByZXYoKTticmVhaztjYXNlIDQwOmUucHJldmVudERlZmF1bHQoKSx0aGlzLm5leHQo
KX1lLnN0b3BQcm9wYWdhdGlvbigpfSxrZXlkb3duOmZ1bmN0aW9uKHQpe3RoaXMuc3VwcHJlc3NLZXlQ
cmVzc1JlcGVhdD1+ZS5pbkFycmF5KHQua2V5Q29kZSxbNDAsMzgsOSwxMywyN10pLHRoaXMubW92ZSh0
KX0sa2V5cHJlc3M6ZnVuY3Rpb24oZSl7aWYodGhpcy5zdXBwcmVzc0tleVByZXNzUmVwZWF0KXJldHVy
bjt0aGlzLm1vdmUoZSl9LGtleXVwOmZ1bmN0aW9uKGUpe3N3aXRjaChlLmtleUNvZGUpe2Nhc2UgNDA6
Y2FzZSAzODpjYXNlIDE2OmNhc2UgMTc6Y2FzZSAxODpicmVhaztjYXNlIDk6Y2FzZSAxMzppZighdGhp
cy5zaG93bilyZXR1cm47dGhpcy5zZWxlY3QoKTticmVhaztjYXNlIDI3OmlmKCF0aGlzLnNob3duKXJl
dHVybjt0aGlzLmhpZGUoKTticmVhaztkZWZhdWx0OnRoaXMubG9va3VwKCl9ZS5zdG9wUHJvcGFnYXRp
b24oKSxlLnByZXZlbnREZWZhdWx0KCl9LGZvY3VzOmZ1bmN0aW9uKGUpe3RoaXMuZm9jdXNlZD0hMH0s
Ymx1cjpmdW5jdGlvbihlKXt0aGlzLmZvY3VzZWQ9ITEsIXRoaXMubW91c2Vkb3ZlciYmdGhpcy5zaG93
biYmdGhpcy5oaWRlKCl9LGNsaWNrOmZ1bmN0aW9uKGUpe2Uuc3RvcFByb3BhZ2F0aW9uKCksZS5wcmV2
ZW50RGVmYXVsdCgpLHRoaXMuc2VsZWN0KCksdGhpcy4kZWxlbWVudC5mb2N1cygpfSxtb3VzZWVudGVy
OmZ1bmN0aW9uKHQpe3RoaXMubW91c2Vkb3Zlcj0hMCx0aGlzLiRtZW51LmZpbmQoIi5hY3RpdmUiKS5y
ZW1vdmVDbGFzcygiYWN0aXZlIiksZSh0LmN1cnJlbnRUYXJnZXQpLmFkZENsYXNzKCJhY3RpdmUiKX0s
bW91c2VsZWF2ZTpmdW5jdGlvbihlKXt0aGlzLm1vdXNlZG92ZXI9ITEsIXRoaXMuZm9jdXNlZCYmdGhp
cy5zaG93biYmdGhpcy5oaWRlKCl9fTt2YXIgbj1lLmZuLnR5cGVhaGVhZDtlLmZuLnR5cGVhaGVhZD1m
dW5jdGlvbihuKXtyZXR1cm4gdGhpcy5lYWNoKGZ1bmN0aW9uKCl7dmFyIHI9ZSh0aGlzKSxpPXIuZGF0
YSgidHlwZWFoZWFkIikscz10eXBlb2Ygbj09Im9iamVjdCImJm47aXx8ci5kYXRhKCJ0eXBlYWhlYWQi
LGk9bmV3IHQodGhpcyxzKSksdHlwZW9mIG49PSJzdHJpbmciJiZpW25dKCl9KX0sZS5mbi50eXBlYWhl
YWQuZGVmYXVsdHM9e3NvdXJjZTpbXSxpdGVtczo4LG1lbnU6Jzx1bCBjbGFzcz0idHlwZWFoZWFkIGRy
b3Bkb3duLW1lbnUiPjwvdWw+JyxpdGVtOic8bGk+PGEgaHJlZj0iIyI+PC9hPjwvbGk+JyxtaW5MZW5n
dGg6MX0sZS5mbi50eXBlYWhlYWQuQ29uc3RydWN0b3I9dCxlLmZuLnR5cGVhaGVhZC5ub0NvbmZsaWN0
PWZ1bmN0aW9uKCl7cmV0dXJuIGUuZm4udHlwZWFoZWFkPW4sdGhpc30sZShkb2N1bWVudCkub24oImZv
Y3VzLnR5cGVhaGVhZC5kYXRhLWFwaSIsJ1tkYXRhLXByb3ZpZGU9InR5cGVhaGVhZCJdJyxmdW5jdGlv
bih0KXt2YXIgbj1lKHRoaXMpO2lmKG4uZGF0YSgidHlwZWFoZWFkIikpcmV0dXJuO24udHlwZWFoZWFk
KG4uZGF0YSgpKX0pfSh3aW5kb3cualF1ZXJ5KSwhZnVuY3Rpb24oZSl7InVzZSBzdHJpY3QiO3ZhciB0
PWZ1bmN0aW9uKHQsbil7dGhpcy5vcHRpb25zPWUuZXh0ZW5kKHt9LGUuZm4uYWZmaXguZGVmYXVsdHMs
biksdGhpcy4kd2luZG93PWUod2luZG93KS5vbigic2Nyb2xsLmFmZml4LmRhdGEtYXBpIixlLnByb3h5
KHRoaXMuY2hlY2tQb3NpdGlvbix0aGlzKSkub24oImNsaWNrLmFmZml4LmRhdGEtYXBpIixlLnByb3h5
KGZ1bmN0aW9uKCl7c2V0VGltZW91dChlLnByb3h5KHRoaXMuY2hlY2tQb3NpdGlvbix0aGlzKSwxKX0s
dGhpcykpLHRoaXMuJGVsZW1lbnQ9ZSh0KSx0aGlzLmNoZWNrUG9zaXRpb24oKX07dC5wcm90b3R5cGUu
Y2hlY2tQb3NpdGlvbj1mdW5jdGlvbigpe2lmKCF0aGlzLiRlbGVtZW50LmlzKCI6dmlzaWJsZSIpKXJl
dHVybjt2YXIgdD1lKGRvY3VtZW50KS5oZWlnaHQoKSxuPXRoaXMuJHdpbmRvdy5zY3JvbGxUb3AoKSxy
PXRoaXMuJGVsZW1lbnQub2Zmc2V0KCksaT10aGlzLm9wdGlvbnMub2Zmc2V0LHM9aS5ib3R0b20sbz1p
LnRvcCx1PSJhZmZpeCBhZmZpeC10b3AgYWZmaXgtYm90dG9tIixhO3R5cGVvZiBpIT0ib2JqZWN0IiYm
KHM9bz1pKSx0eXBlb2Ygbz09ImZ1bmN0aW9uIiYmKG89aS50b3AoKSksdHlwZW9mIHM9PSJmdW5jdGlv
biImJihzPWkuYm90dG9tKCkpLGE9dGhpcy51bnBpbiE9bnVsbCYmbit0aGlzLnVucGluPD1yLnRvcD8h
MTpzIT1udWxsJiZyLnRvcCt0aGlzLiRlbGVtZW50LmhlaWdodCgpPj10LXM/ImJvdHRvbSI6byE9bnVs
bCYmbjw9bz8idG9wIjohMTtpZih0aGlzLmFmZml4ZWQ9PT1hKXJldHVybjt0aGlzLmFmZml4ZWQ9YSx0
aGlzLnVucGluPWE9PSJib3R0b20iP3IudG9wLW46bnVsbCx0aGlzLiRlbGVtZW50LnJlbW92ZUNsYXNz
KHUpLmFkZENsYXNzKCJhZmZpeCIrKGE/Ii0iK2E6IiIpKX07dmFyIG49ZS5mbi5hZmZpeDtlLmZuLmFm
Zml4PWZ1bmN0aW9uKG4pe3JldHVybiB0aGlzLmVhY2goZnVuY3Rpb24oKXt2YXIgcj1lKHRoaXMpLGk9
ci5kYXRhKCJhZmZpeCIpLHM9dHlwZW9mIG49PSJvYmplY3QiJiZuO2l8fHIuZGF0YSgiYWZmaXgiLGk9
bmV3IHQodGhpcyxzKSksdHlwZW9mIG49PSJzdHJpbmciJiZpW25dKCl9KX0sZS5mbi5hZmZpeC5Db25z
dHJ1Y3Rvcj10LGUuZm4uYWZmaXguZGVmYXVsdHM9e29mZnNldDowfSxlLmZuLmFmZml4Lm5vQ29uZmxp
Y3Q9ZnVuY3Rpb24oKXtyZXR1cm4gZS5mbi5hZmZpeD1uLHRoaXN9LGUod2luZG93KS5vbigibG9hZCIs
ZnVuY3Rpb24oKXtlKCdbZGF0YS1zcHk9ImFmZml4Il0nKS5lYWNoKGZ1bmN0aW9uKCl7dmFyIHQ9ZSh0
aGlzKSxuPXQuZGF0YSgpO24ub2Zmc2V0PW4ub2Zmc2V0fHx7fSxuLm9mZnNldEJvdHRvbSYmKG4ub2Zm
c2V0LmJvdHRvbT1uLm9mZnNldEJvdHRvbSksbi5vZmZzZXRUb3AmJihuLm9mZnNldC50b3A9bi5vZmZz
ZXRUb3ApLHQuYWZmaXgobil9KX0pfSh3aW5kb3cualF1ZXJ5KTs=

@@ bootstrap_min_css
LyohCiAqIEJvb3RzdHJhcCB2Mi4zLjAKICoKICogQ29weXJpZ2h0IDIwMTIgVHdpdHRlciwgSW5jCiAq
IExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSB2Mi4wCiAqIGh0dHA6Ly93d3cuYXBhY2hl
Lm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAogKgogKiBEZXNpZ25lZCBhbmQgYnVpbHQgd2l0aCBhbGwg
dGhlIGxvdmUgaW4gdGhlIHdvcmxkIEB0d2l0dGVyIGJ5IEBtZG8gYW5kIEBmYXQuCiAqLy5jbGVhcmZp
eHsqem9vbToxfS5jbGVhcmZpeDpiZWZvcmUsLmNsZWFyZml4OmFmdGVye2Rpc3BsYXk6dGFibGU7bGlu
ZS1oZWlnaHQ6MDtjb250ZW50OiIifS5jbGVhcmZpeDphZnRlcntjbGVhcjpib3RofS5oaWRlLXRleHR7
Zm9udDowLzAgYTtjb2xvcjp0cmFuc3BhcmVudDt0ZXh0LXNoYWRvdzpub25lO2JhY2tncm91bmQtY29s
b3I6dHJhbnNwYXJlbnQ7Ym9yZGVyOjB9LmlucHV0LWJsb2NrLWxldmVse2Rpc3BsYXk6YmxvY2s7d2lk
dGg6MTAwJTttaW4taGVpZ2h0OjMwcHg7LXdlYmtpdC1ib3gtc2l6aW5nOmJvcmRlci1ib3g7LW1vei1i
b3gtc2l6aW5nOmJvcmRlci1ib3g7Ym94LXNpemluZzpib3JkZXItYm94fWFydGljbGUsYXNpZGUsZGV0
YWlscyxmaWdjYXB0aW9uLGZpZ3VyZSxmb290ZXIsaGVhZGVyLGhncm91cCxuYXYsc2VjdGlvbntkaXNw
bGF5OmJsb2NrfWF1ZGlvLGNhbnZhcyx2aWRlb3tkaXNwbGF5OmlubGluZS1ibG9jazsqZGlzcGxheTpp
bmxpbmU7Knpvb206MX1hdWRpbzpub3QoW2NvbnRyb2xzXSl7ZGlzcGxheTpub25lfWh0bWx7Zm9udC1z
aXplOjEwMCU7LXdlYmtpdC10ZXh0LXNpemUtYWRqdXN0OjEwMCU7LW1zLXRleHQtc2l6ZS1hZGp1c3Q6
MTAwJX1hOmZvY3Vze291dGxpbmU6dGhpbiBkb3R0ZWQgIzMzMztvdXRsaW5lOjVweCBhdXRvIC13ZWJr
aXQtZm9jdXMtcmluZy1jb2xvcjtvdXRsaW5lLW9mZnNldDotMnB4fWE6aG92ZXIsYTphY3RpdmV7b3V0
bGluZTowfXN1YixzdXB7cG9zaXRpb246cmVsYXRpdmU7Zm9udC1zaXplOjc1JTtsaW5lLWhlaWdodDow
O3ZlcnRpY2FsLWFsaWduOmJhc2VsaW5lfXN1cHt0b3A6LTAuNWVtfXN1Yntib3R0b206LTAuMjVlbX1p
bWd7d2lkdGg6YXV0b1w5O2hlaWdodDphdXRvO21heC13aWR0aDoxMDAlO3ZlcnRpY2FsLWFsaWduOm1p
ZGRsZTtib3JkZXI6MDstbXMtaW50ZXJwb2xhdGlvbi1tb2RlOmJpY3ViaWN9I21hcF9jYW52YXMgaW1n
LC5nb29nbGUtbWFwcyBpbWd7bWF4LXdpZHRoOm5vbmV9YnV0dG9uLGlucHV0LHNlbGVjdCx0ZXh0YXJl
YXttYXJnaW46MDtmb250LXNpemU6MTAwJTt2ZXJ0aWNhbC1hbGlnbjptaWRkbGV9YnV0dG9uLGlucHV0
eypvdmVyZmxvdzp2aXNpYmxlO2xpbmUtaGVpZ2h0Om5vcm1hbH1idXR0b246Oi1tb3otZm9jdXMtaW5u
ZXIsaW5wdXQ6Oi1tb3otZm9jdXMtaW5uZXJ7cGFkZGluZzowO2JvcmRlcjowfWJ1dHRvbixodG1sIGlu
cHV0W3R5cGU9ImJ1dHRvbiJdLGlucHV0W3R5cGU9InJlc2V0Il0saW5wdXRbdHlwZT0ic3VibWl0Il17
Y3Vyc29yOnBvaW50ZXI7LXdlYmtpdC1hcHBlYXJhbmNlOmJ1dHRvbn1sYWJlbCxzZWxlY3QsYnV0dG9u
LGlucHV0W3R5cGU9ImJ1dHRvbiJdLGlucHV0W3R5cGU9InJlc2V0Il0saW5wdXRbdHlwZT0ic3VibWl0
Il0saW5wdXRbdHlwZT0icmFkaW8iXSxpbnB1dFt0eXBlPSJjaGVja2JveCJde2N1cnNvcjpwb2ludGVy
fWlucHV0W3R5cGU9InNlYXJjaCJdey13ZWJraXQtYm94LXNpemluZzpjb250ZW50LWJveDstbW96LWJv
eC1zaXppbmc6Y29udGVudC1ib3g7Ym94LXNpemluZzpjb250ZW50LWJveDstd2Via2l0LWFwcGVhcmFu
Y2U6dGV4dGZpZWxkfWlucHV0W3R5cGU9InNlYXJjaCJdOjotd2Via2l0LXNlYXJjaC1kZWNvcmF0aW9u
LGlucHV0W3R5cGU9InNlYXJjaCJdOjotd2Via2l0LXNlYXJjaC1jYW5jZWwtYnV0dG9uey13ZWJraXQt
YXBwZWFyYW5jZTpub25lfXRleHRhcmVhe292ZXJmbG93OmF1dG87dmVydGljYWwtYWxpZ246dG9wfUBt
ZWRpYSBwcmludHsqe2NvbG9yOiMwMDAhaW1wb3J0YW50O3RleHQtc2hhZG93Om5vbmUhaW1wb3J0YW50
O2JhY2tncm91bmQ6dHJhbnNwYXJlbnQhaW1wb3J0YW50O2JveC1zaGFkb3c6bm9uZSFpbXBvcnRhbnR9
YSxhOnZpc2l0ZWR7dGV4dC1kZWNvcmF0aW9uOnVuZGVybGluZX1hW2hyZWZdOmFmdGVye2NvbnRlbnQ6
IiAoIiBhdHRyKGhyZWYpICIpIn1hYmJyW3RpdGxlXTphZnRlcntjb250ZW50OiIgKCIgYXR0cih0aXRs
ZSkgIikifS5pciBhOmFmdGVyLGFbaHJlZl49ImphdmFzY3JpcHQ6Il06YWZ0ZXIsYVtocmVmXj0iIyJd
OmFmdGVye2NvbnRlbnQ6IiJ9cHJlLGJsb2NrcXVvdGV7Ym9yZGVyOjFweCBzb2xpZCAjOTk5O3BhZ2Ut
YnJlYWstaW5zaWRlOmF2b2lkfXRoZWFke2Rpc3BsYXk6dGFibGUtaGVhZGVyLWdyb3VwfXRyLGltZ3tw
YWdlLWJyZWFrLWluc2lkZTphdm9pZH1pbWd7bWF4LXdpZHRoOjEwMCUhaW1wb3J0YW50fUBwYWdle21h
cmdpbjouNWNtfXAsaDIsaDN7b3JwaGFuczozO3dpZG93czozfWgyLGgze3BhZ2UtYnJlYWstYWZ0ZXI6
YXZvaWR9fWJvZHl7bWFyZ2luOjA7Zm9udC1mYW1pbHk6IkhlbHZldGljYSBOZXVlIixIZWx2ZXRpY2Es
QXJpYWwsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweDtsaW5lLWhlaWdodDoyMHB4O2NvbG9yOiMzMzM7
YmFja2dyb3VuZC1jb2xvcjojZmZmfWF7Y29sb3I6IzA4Yzt0ZXh0LWRlY29yYXRpb246bm9uZX1hOmhv
dmVyLGE6Zm9jdXN7Y29sb3I6IzAwNTU4MDt0ZXh0LWRlY29yYXRpb246dW5kZXJsaW5lfS5pbWctcm91
bmRlZHstd2Via2l0LWJvcmRlci1yYWRpdXM6NnB4Oy1tb3otYm9yZGVyLXJhZGl1czo2cHg7Ym9yZGVy
LXJhZGl1czo2cHh9LmltZy1wb2xhcm9pZHtwYWRkaW5nOjRweDtiYWNrZ3JvdW5kLWNvbG9yOiNmZmY7
Ym9yZGVyOjFweCBzb2xpZCAjY2NjO2JvcmRlcjoxcHggc29saWQgcmdiYSgwLDAsMCwwLjIpOy13ZWJr
aXQtYm94LXNoYWRvdzowIDFweCAzcHggcmdiYSgwLDAsMCwwLjEpOy1tb3otYm94LXNoYWRvdzowIDFw
eCAzcHggcmdiYSgwLDAsMCwwLjEpO2JveC1zaGFkb3c6MCAxcHggM3B4IHJnYmEoMCwwLDAsMC4xKX0u
aW1nLWNpcmNsZXstd2Via2l0LWJvcmRlci1yYWRpdXM6NTAwcHg7LW1vei1ib3JkZXItcmFkaXVzOjUw
MHB4O2JvcmRlci1yYWRpdXM6NTAwcHh9LnJvd3ttYXJnaW4tbGVmdDotMjBweDsqem9vbToxfS5yb3c6
YmVmb3JlLC5yb3c6YWZ0ZXJ7ZGlzcGxheTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9LnJv
dzphZnRlcntjbGVhcjpib3RofVtjbGFzcyo9InNwYW4iXXtmbG9hdDpsZWZ0O21pbi1oZWlnaHQ6MXB4
O21hcmdpbi1sZWZ0OjIwcHh9LmNvbnRhaW5lciwubmF2YmFyLXN0YXRpYy10b3AgLmNvbnRhaW5lciwu
bmF2YmFyLWZpeGVkLXRvcCAuY29udGFpbmVyLC5uYXZiYXItZml4ZWQtYm90dG9tIC5jb250YWluZXJ7
d2lkdGg6OTQwcHh9LnNwYW4xMnt3aWR0aDo5NDBweH0uc3BhbjExe3dpZHRoOjg2MHB4fS5zcGFuMTB7
d2lkdGg6NzgwcHh9LnNwYW45e3dpZHRoOjcwMHB4fS5zcGFuOHt3aWR0aDo2MjBweH0uc3Bhbjd7d2lk
dGg6NTQwcHh9LnNwYW42e3dpZHRoOjQ2MHB4fS5zcGFuNXt3aWR0aDozODBweH0uc3BhbjR7d2lkdGg6
MzAwcHh9LnNwYW4ze3dpZHRoOjIyMHB4fS5zcGFuMnt3aWR0aDoxNDBweH0uc3BhbjF7d2lkdGg6NjBw
eH0ub2Zmc2V0MTJ7bWFyZ2luLWxlZnQ6OTgwcHh9Lm9mZnNldDExe21hcmdpbi1sZWZ0OjkwMHB4fS5v
ZmZzZXQxMHttYXJnaW4tbGVmdDo4MjBweH0ub2Zmc2V0OXttYXJnaW4tbGVmdDo3NDBweH0ub2Zmc2V0
OHttYXJnaW4tbGVmdDo2NjBweH0ub2Zmc2V0N3ttYXJnaW4tbGVmdDo1ODBweH0ub2Zmc2V0NnttYXJn
aW4tbGVmdDo1MDBweH0ub2Zmc2V0NXttYXJnaW4tbGVmdDo0MjBweH0ub2Zmc2V0NHttYXJnaW4tbGVm
dDozNDBweH0ub2Zmc2V0M3ttYXJnaW4tbGVmdDoyNjBweH0ub2Zmc2V0MnttYXJnaW4tbGVmdDoxODBw
eH0ub2Zmc2V0MXttYXJnaW4tbGVmdDoxMDBweH0ucm93LWZsdWlke3dpZHRoOjEwMCU7Knpvb206MX0u
cm93LWZsdWlkOmJlZm9yZSwucm93LWZsdWlkOmFmdGVye2Rpc3BsYXk6dGFibGU7bGluZS1oZWlnaHQ6
MDtjb250ZW50OiIifS5yb3ctZmx1aWQ6YWZ0ZXJ7Y2xlYXI6Ym90aH0ucm93LWZsdWlkIFtjbGFzcyo9
InNwYW4iXXtkaXNwbGF5OmJsb2NrO2Zsb2F0OmxlZnQ7d2lkdGg6MTAwJTttaW4taGVpZ2h0OjMwcHg7
bWFyZ2luLWxlZnQ6Mi4xMjc2NTk1NzQ0NjgwODUlOyptYXJnaW4tbGVmdDoyLjA3NDQ2ODA4NTEwNjM4
MyU7LXdlYmtpdC1ib3gtc2l6aW5nOmJvcmRlci1ib3g7LW1vei1ib3gtc2l6aW5nOmJvcmRlci1ib3g7
Ym94LXNpemluZzpib3JkZXItYm94fS5yb3ctZmx1aWQgW2NsYXNzKj0ic3BhbiJdOmZpcnN0LWNoaWxk
e21hcmdpbi1sZWZ0OjB9LnJvdy1mbHVpZCAuY29udHJvbHMtcm93IFtjbGFzcyo9InNwYW4iXStbY2xh
c3MqPSJzcGFuIl17bWFyZ2luLWxlZnQ6Mi4xMjc2NTk1NzQ0NjgwODUlfS5yb3ctZmx1aWQgLnNwYW4x
Mnt3aWR0aDoxMDAlOyp3aWR0aDo5OS45NDY4MDg1MTA2MzgyOSV9LnJvdy1mbHVpZCAuc3BhbjExe3dp
ZHRoOjkxLjQ4OTM2MTcwMjEyNzY1JTsqd2lkdGg6OTEuNDM2MTcwMjEyNzY1OTQlfS5yb3ctZmx1aWQg
LnNwYW4xMHt3aWR0aDo4Mi45Nzg3MjM0MDQyNTUzMiU7KndpZHRoOjgyLjkyNTUzMTkxNDg5MzYxJX0u
cm93LWZsdWlkIC5zcGFuOXt3aWR0aDo3NC40NjgwODUxMDYzODI5NyU7KndpZHRoOjc0LjQxNDg5MzYx
NzAyMTI2JX0ucm93LWZsdWlkIC5zcGFuOHt3aWR0aDo2NS45NTc0NDY4MDg1MTA2NCU7KndpZHRoOjY1
LjkwNDI1NTMxOTE0ODkzJX0ucm93LWZsdWlkIC5zcGFuN3t3aWR0aDo1Ny40NDY4MDg1MTA2MzgyOSU7
KndpZHRoOjU3LjM5MzYxNzAyMTI3NjU5JX0ucm93LWZsdWlkIC5zcGFuNnt3aWR0aDo0OC45MzYxNzAy
MTI3NjU5NSU7KndpZHRoOjQ4Ljg4Mjk3ODcyMzQwNDI1JX0ucm93LWZsdWlkIC5zcGFuNXt3aWR0aDo0
MC40MjU1MzE5MTQ4OTM2MiU7KndpZHRoOjQwLjM3MjM0MDQyNTUzMTkyJX0ucm93LWZsdWlkIC5zcGFu
NHt3aWR0aDozMS45MTQ4OTM2MTcwMjEyNzglOyp3aWR0aDozMS44NjE3MDIxMjc2NTk1NzYlfS5yb3ct
Zmx1aWQgLnNwYW4ze3dpZHRoOjIzLjQwNDI1NTMxOTE0ODkzNCU7KndpZHRoOjIzLjM1MTA2MzgyOTc4
NzIzMyV9LnJvdy1mbHVpZCAuc3BhbjJ7d2lkdGg6MTQuODkzNjE3MDIxMjc2NTk1JTsqd2lkdGg6MTQu
ODQwNDI1NTMxOTE0ODk0JX0ucm93LWZsdWlkIC5zcGFuMXt3aWR0aDo2LjM4Mjk3ODcyMzQwNDI1NSU7
KndpZHRoOjYuMzI5Nzg3MjM0MDQyNTUzJX0ucm93LWZsdWlkIC5vZmZzZXQxMnttYXJnaW4tbGVmdDox
MDQuMjU1MzE5MTQ4OTM2MTclOyptYXJnaW4tbGVmdDoxMDQuMTQ4OTM2MTcwMjEyNzUlfS5yb3ctZmx1
aWQgLm9mZnNldDEyOmZpcnN0LWNoaWxke21hcmdpbi1sZWZ0OjEwMi4xMjc2NTk1NzQ0NjgwOCU7Km1h
cmdpbi1sZWZ0OjEwMi4wMjEyNzY1OTU3NDQ2NyV9LnJvdy1mbHVpZCAub2Zmc2V0MTF7bWFyZ2luLWxl
ZnQ6OTUuNzQ0NjgwODUxMDYzODIlOyptYXJnaW4tbGVmdDo5NS42MzgyOTc4NzIzNDA0JX0ucm93LWZs
dWlkIC5vZmZzZXQxMTpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo5My42MTcwMjEyNzY1OTU3NCU7Km1h
cmdpbi1sZWZ0OjkzLjUxMDYzODI5Nzg3MjMyJX0ucm93LWZsdWlkIC5vZmZzZXQxMHttYXJnaW4tbGVm
dDo4Ny4yMzQwNDI1NTMxOTE0OSU7Km1hcmdpbi1sZWZ0Ojg3LjEyNzY1OTU3NDQ2ODA3JX0ucm93LWZs
dWlkIC5vZmZzZXQxMDpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo4NS4xMDYzODI5Nzg3MjM0JTsqbWFy
Z2luLWxlZnQ6ODQuOTk5OTk5OTk5OTk5OTklfS5yb3ctZmx1aWQgLm9mZnNldDl7bWFyZ2luLWxlZnQ6
NzguNzIzNDA0MjU1MzE5MTQlOyptYXJnaW4tbGVmdDo3OC42MTcwMjEyNzY1OTU3MiV9LnJvdy1mbHVp
ZCAub2Zmc2V0OTpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo3Ni41OTU3NDQ2ODA4NTEwNiU7Km1hcmdp
bi1sZWZ0Ojc2LjQ4OTM2MTcwMjEyNzY0JX0ucm93LWZsdWlkIC5vZmZzZXQ4e21hcmdpbi1sZWZ0Ojcw
LjIxMjc2NTk1NzQ0NjglOyptYXJnaW4tbGVmdDo3MC4xMDYzODI5Nzg3MjMzOSV9LnJvdy1mbHVpZCAu
b2Zmc2V0ODpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo2OC4wODUxMDYzODI5Nzg3MiU7Km1hcmdpbi1s
ZWZ0OjY3Ljk3ODcyMzQwNDI1NTMlfS5yb3ctZmx1aWQgLm9mZnNldDd7bWFyZ2luLWxlZnQ6NjEuNzAy
MTI3NjU5NTc0NDYlOyptYXJnaW4tbGVmdDo2MS41OTU3NDQ2ODA4NTEwNiV9LnJvdy1mbHVpZCAub2Zm
c2V0NzpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo1OS41NzQ0NjgwODUxMDYzNzUlOyptYXJnaW4tbGVm
dDo1OS40NjgwODUxMDYzODI5NyV9LnJvdy1mbHVpZCAub2Zmc2V0NnttYXJnaW4tbGVmdDo1My4xOTE0
ODkzNjE3MDIxMjUlOyptYXJnaW4tbGVmdDo1My4wODUxMDYzODI5Nzg3MTUlfS5yb3ctZmx1aWQgLm9m
ZnNldDY6Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6NTEuMDYzODI5Nzg3MjM0MDM1JTsqbWFyZ2luLWxl
ZnQ6NTAuOTU3NDQ2ODA4NTEwNjMlfS5yb3ctZmx1aWQgLm9mZnNldDV7bWFyZ2luLWxlZnQ6NDQuNjgw
ODUxMDYzODI5NzklOyptYXJnaW4tbGVmdDo0NC41NzQ0NjgwODUxMDYzOCV9LnJvdy1mbHVpZCAub2Zm
c2V0NTpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo0Mi41NTMxOTE0ODkzNjE3JTsqbWFyZ2luLWxlZnQ6
NDIuNDQ2ODA4NTEwNjM4MyV9LnJvdy1mbHVpZCAub2Zmc2V0NHttYXJnaW4tbGVmdDozNi4xNzAyMTI3
NjU5NTc0NDQlOyptYXJnaW4tbGVmdDozNi4wNjM4Mjk3ODcyMzQwNSV9LnJvdy1mbHVpZCAub2Zmc2V0
NDpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDozNC4wNDI1NTMxOTE0ODkzNiU7Km1hcmdpbi1sZWZ0OjMz
LjkzNjE3MDIxMjc2NTk2JX0ucm93LWZsdWlkIC5vZmZzZXQze21hcmdpbi1sZWZ0OjI3LjY1OTU3NDQ2
ODA4NTEwNCU7Km1hcmdpbi1sZWZ0OjI3LjU1MzE5MTQ4OTM2MTclfS5yb3ctZmx1aWQgLm9mZnNldDM6
Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6MjUuNTMxOTE0ODkzNjE3MDIlOyptYXJnaW4tbGVmdDoyNS40
MjU1MzE5MTQ4OTM2MTglfS5yb3ctZmx1aWQgLm9mZnNldDJ7bWFyZ2luLWxlZnQ6MTkuMTQ4OTM2MTcw
MjEyNzY0JTsqbWFyZ2luLWxlZnQ6MTkuMDQyNTUzMTkxNDg5MzYlfS5yb3ctZmx1aWQgLm9mZnNldDI6
Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6MTcuMDIxMjc2NTk1NzQ0NjglOyptYXJnaW4tbGVmdDoxNi45
MTQ4OTM2MTcwMjEyNzglfS5yb3ctZmx1aWQgLm9mZnNldDF7bWFyZ2luLWxlZnQ6MTAuNjM4Mjk3ODcy
MzQwNDI1JTsqbWFyZ2luLWxlZnQ6MTAuNTMxOTE0ODkzNjE3MDIlfS5yb3ctZmx1aWQgLm9mZnNldDE6
Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6OC41MTA2MzgyOTc4NzIzNCU7Km1hcmdpbi1sZWZ0OjguNDA0
MjU1MzE5MTQ4OTM4JX1bY2xhc3MqPSJzcGFuIl0uaGlkZSwucm93LWZsdWlkIFtjbGFzcyo9InNwYW4i
XS5oaWRle2Rpc3BsYXk6bm9uZX1bY2xhc3MqPSJzcGFuIl0ucHVsbC1yaWdodCwucm93LWZsdWlkIFtj
bGFzcyo9InNwYW4iXS5wdWxsLXJpZ2h0e2Zsb2F0OnJpZ2h0fS5jb250YWluZXJ7bWFyZ2luLXJpZ2h0
OmF1dG87bWFyZ2luLWxlZnQ6YXV0bzsqem9vbToxfS5jb250YWluZXI6YmVmb3JlLC5jb250YWluZXI6
YWZ0ZXJ7ZGlzcGxheTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9LmNvbnRhaW5lcjphZnRl
cntjbGVhcjpib3RofS5jb250YWluZXItZmx1aWR7cGFkZGluZy1yaWdodDoyMHB4O3BhZGRpbmctbGVm
dDoyMHB4Oyp6b29tOjF9LmNvbnRhaW5lci1mbHVpZDpiZWZvcmUsLmNvbnRhaW5lci1mbHVpZDphZnRl
cntkaXNwbGF5OnRhYmxlO2xpbmUtaGVpZ2h0OjA7Y29udGVudDoiIn0uY29udGFpbmVyLWZsdWlkOmFm
dGVye2NsZWFyOmJvdGh9cHttYXJnaW46MCAwIDEwcHh9LmxlYWR7bWFyZ2luLWJvdHRvbToyMHB4O2Zv
bnQtc2l6ZToyMXB4O2ZvbnQtd2VpZ2h0OjIwMDtsaW5lLWhlaWdodDozMHB4fXNtYWxse2ZvbnQtc2l6
ZTo4NSV9c3Ryb25ne2ZvbnQtd2VpZ2h0OmJvbGR9ZW17Zm9udC1zdHlsZTppdGFsaWN9Y2l0ZXtmb250
LXN0eWxlOm5vcm1hbH0ubXV0ZWR7Y29sb3I6Izk5OX1hLm11dGVkOmhvdmVyLGEubXV0ZWQ6Zm9jdXN7
Y29sb3I6IzgwODA4MH0udGV4dC13YXJuaW5ne2NvbG9yOiNjMDk4NTN9YS50ZXh0LXdhcm5pbmc6aG92
ZXIsYS50ZXh0LXdhcm5pbmc6Zm9jdXN7Y29sb3I6I2E0N2UzY30udGV4dC1lcnJvcntjb2xvcjojYjk0
YTQ4fWEudGV4dC1lcnJvcjpob3ZlcixhLnRleHQtZXJyb3I6Zm9jdXN7Y29sb3I6Izk1M2IzOX0udGV4
dC1pbmZve2NvbG9yOiMzYTg3YWR9YS50ZXh0LWluZm86aG92ZXIsYS50ZXh0LWluZm86Zm9jdXN7Y29s
b3I6IzJkNjk4N30udGV4dC1zdWNjZXNze2NvbG9yOiM0Njg4NDd9YS50ZXh0LXN1Y2Nlc3M6aG92ZXIs
YS50ZXh0LXN1Y2Nlc3M6Zm9jdXN7Y29sb3I6IzM1NjYzNX0udGV4dC1sZWZ0e3RleHQtYWxpZ246bGVm
dH0udGV4dC1yaWdodHt0ZXh0LWFsaWduOnJpZ2h0fS50ZXh0LWNlbnRlcnt0ZXh0LWFsaWduOmNlbnRl
cn1oMSxoMixoMyxoNCxoNSxoNnttYXJnaW46MTBweCAwO2ZvbnQtZmFtaWx5OmluaGVyaXQ7Zm9udC13
ZWlnaHQ6Ym9sZDtsaW5lLWhlaWdodDoyMHB4O2NvbG9yOmluaGVyaXQ7dGV4dC1yZW5kZXJpbmc6b3B0
aW1pemVsZWdpYmlsaXR5fWgxIHNtYWxsLGgyIHNtYWxsLGgzIHNtYWxsLGg0IHNtYWxsLGg1IHNtYWxs
LGg2IHNtYWxse2ZvbnQtd2VpZ2h0Om5vcm1hbDtsaW5lLWhlaWdodDoxO2NvbG9yOiM5OTl9aDEsaDIs
aDN7bGluZS1oZWlnaHQ6NDBweH1oMXtmb250LXNpemU6MzguNXB4fWgye2ZvbnQtc2l6ZTozMS41cHh9
aDN7Zm9udC1zaXplOjI0LjVweH1oNHtmb250LXNpemU6MTcuNXB4fWg1e2ZvbnQtc2l6ZToxNHB4fWg2
e2ZvbnQtc2l6ZToxMS45cHh9aDEgc21hbGx7Zm9udC1zaXplOjI0LjVweH1oMiBzbWFsbHtmb250LXNp
emU6MTcuNXB4fWgzIHNtYWxse2ZvbnQtc2l6ZToxNHB4fWg0IHNtYWxse2ZvbnQtc2l6ZToxNHB4fS5w
YWdlLWhlYWRlcntwYWRkaW5nLWJvdHRvbTo5cHg7bWFyZ2luOjIwcHggMCAzMHB4O2JvcmRlci1ib3R0
b206MXB4IHNvbGlkICNlZWV9dWwsb2x7cGFkZGluZzowO21hcmdpbjowIDAgMTBweCAyNXB4fXVsIHVs
LHVsIG9sLG9sIG9sLG9sIHVse21hcmdpbi1ib3R0b206MH1saXtsaW5lLWhlaWdodDoyMHB4fXVsLnVu
c3R5bGVkLG9sLnVuc3R5bGVke21hcmdpbi1sZWZ0OjA7bGlzdC1zdHlsZTpub25lfXVsLmlubGluZSxv
bC5pbmxpbmV7bWFyZ2luLWxlZnQ6MDtsaXN0LXN0eWxlOm5vbmV9dWwuaW5saW5lPmxpLG9sLmlubGlu
ZT5saXtkaXNwbGF5OmlubGluZS1ibG9jazsqZGlzcGxheTppbmxpbmU7cGFkZGluZy1yaWdodDo1cHg7
cGFkZGluZy1sZWZ0OjVweDsqem9vbToxfWRse21hcmdpbi1ib3R0b206MjBweH1kdCxkZHtsaW5lLWhl
aWdodDoyMHB4fWR0e2ZvbnQtd2VpZ2h0OmJvbGR9ZGR7bWFyZ2luLWxlZnQ6MTBweH0uZGwtaG9yaXpv
bnRhbHsqem9vbToxfS5kbC1ob3Jpem9udGFsOmJlZm9yZSwuZGwtaG9yaXpvbnRhbDphZnRlcntkaXNw
bGF5OnRhYmxlO2xpbmUtaGVpZ2h0OjA7Y29udGVudDoiIn0uZGwtaG9yaXpvbnRhbDphZnRlcntjbGVh
cjpib3RofS5kbC1ob3Jpem9udGFsIGR0e2Zsb2F0OmxlZnQ7d2lkdGg6MTYwcHg7b3ZlcmZsb3c6aGlk
ZGVuO2NsZWFyOmxlZnQ7dGV4dC1hbGlnbjpyaWdodDt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzO3doaXRl
LXNwYWNlOm5vd3JhcH0uZGwtaG9yaXpvbnRhbCBkZHttYXJnaW4tbGVmdDoxODBweH1ocnttYXJnaW46
MjBweCAwO2JvcmRlcjowO2JvcmRlci10b3A6MXB4IHNvbGlkICNlZWU7Ym9yZGVyLWJvdHRvbToxcHgg
c29saWQgI2ZmZn1hYmJyW3RpdGxlXSxhYmJyW2RhdGEtb3JpZ2luYWwtdGl0bGVde2N1cnNvcjpoZWxw
O2JvcmRlci1ib3R0b206MXB4IGRvdHRlZCAjOTk5fWFiYnIuaW5pdGlhbGlzbXtmb250LXNpemU6OTAl
O3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX1ibG9ja3F1b3Rle3BhZGRpbmc6MCAwIDAgMTVweDttYXJn
aW46MCAwIDIwcHg7Ym9yZGVyLWxlZnQ6NXB4IHNvbGlkICNlZWV9YmxvY2txdW90ZSBwe21hcmdpbi1i
b3R0b206MDtmb250LXNpemU6MTcuNXB4O2ZvbnQtd2VpZ2h0OjMwMDtsaW5lLWhlaWdodDoxLjI1fWJs
b2NrcXVvdGUgc21hbGx7ZGlzcGxheTpibG9jaztsaW5lLWhlaWdodDoyMHB4O2NvbG9yOiM5OTl9Ymxv
Y2txdW90ZSBzbWFsbDpiZWZvcmV7Y29udGVudDonXDIwMTQgXDAwQTAnfWJsb2NrcXVvdGUucHVsbC1y
aWdodHtmbG9hdDpyaWdodDtwYWRkaW5nLXJpZ2h0OjE1cHg7cGFkZGluZy1sZWZ0OjA7Ym9yZGVyLXJp
Z2h0OjVweCBzb2xpZCAjZWVlO2JvcmRlci1sZWZ0OjB9YmxvY2txdW90ZS5wdWxsLXJpZ2h0IHAsYmxv
Y2txdW90ZS5wdWxsLXJpZ2h0IHNtYWxse3RleHQtYWxpZ246cmlnaHR9YmxvY2txdW90ZS5wdWxsLXJp
Z2h0IHNtYWxsOmJlZm9yZXtjb250ZW50OicnfWJsb2NrcXVvdGUucHVsbC1yaWdodCBzbWFsbDphZnRl
cntjb250ZW50OidcMDBBMCBcMjAxNCd9cTpiZWZvcmUscTphZnRlcixibG9ja3F1b3RlOmJlZm9yZSxi
bG9ja3F1b3RlOmFmdGVye2NvbnRlbnQ6IiJ9YWRkcmVzc3tkaXNwbGF5OmJsb2NrO21hcmdpbi1ib3R0
b206MjBweDtmb250LXN0eWxlOm5vcm1hbDtsaW5lLWhlaWdodDoyMHB4fWNvZGUscHJle3BhZGRpbmc6
MCAzcHggMnB4O2ZvbnQtZmFtaWx5Ok1vbmFjbyxNZW5sbyxDb25zb2xhcywiQ291cmllciBOZXciLG1v
bm9zcGFjZTtmb250LXNpemU6MTJweDtjb2xvcjojMzMzOy13ZWJraXQtYm9yZGVyLXJhZGl1czozcHg7
LW1vei1ib3JkZXItcmFkaXVzOjNweDtib3JkZXItcmFkaXVzOjNweH1jb2Rle3BhZGRpbmc6MnB4IDRw
eDtjb2xvcjojZDE0O3doaXRlLXNwYWNlOm5vd3JhcDtiYWNrZ3JvdW5kLWNvbG9yOiNmN2Y3Zjk7Ym9y
ZGVyOjFweCBzb2xpZCAjZTFlMWU4fXByZXtkaXNwbGF5OmJsb2NrO3BhZGRpbmc6OS41cHg7bWFyZ2lu
OjAgMCAxMHB4O2ZvbnQtc2l6ZToxM3B4O2xpbmUtaGVpZ2h0OjIwcHg7d29yZC1icmVhazpicmVhay1h
bGw7d29yZC13cmFwOmJyZWFrLXdvcmQ7d2hpdGUtc3BhY2U6cHJlO3doaXRlLXNwYWNlOnByZS13cmFw
O2JhY2tncm91bmQtY29sb3I6I2Y1ZjVmNTtib3JkZXI6MXB4IHNvbGlkICNjY2M7Ym9yZGVyOjFweCBz
b2xpZCByZ2JhKDAsMCwwLDAuMTUpOy13ZWJraXQtYm9yZGVyLXJhZGl1czo0cHg7LW1vei1ib3JkZXIt
cmFkaXVzOjRweDtib3JkZXItcmFkaXVzOjRweH1wcmUucHJldHR5cHJpbnR7bWFyZ2luLWJvdHRvbToy
MHB4fXByZSBjb2Rle3BhZGRpbmc6MDtjb2xvcjppbmhlcml0O3doaXRlLXNwYWNlOnByZTt3aGl0ZS1z
cGFjZTpwcmUtd3JhcDtiYWNrZ3JvdW5kLWNvbG9yOnRyYW5zcGFyZW50O2JvcmRlcjowfS5wcmUtc2Ny
b2xsYWJsZXttYXgtaGVpZ2h0OjM0MHB4O292ZXJmbG93LXk6c2Nyb2xsfWZvcm17bWFyZ2luOjAgMCAy
MHB4fWZpZWxkc2V0e3BhZGRpbmc6MDttYXJnaW46MDtib3JkZXI6MH1sZWdlbmR7ZGlzcGxheTpibG9j
azt3aWR0aDoxMDAlO3BhZGRpbmc6MDttYXJnaW4tYm90dG9tOjIwcHg7Zm9udC1zaXplOjIxcHg7bGlu
ZS1oZWlnaHQ6NDBweDtjb2xvcjojMzMzO2JvcmRlcjowO2JvcmRlci1ib3R0b206MXB4IHNvbGlkICNl
NWU1ZTV9bGVnZW5kIHNtYWxse2ZvbnQtc2l6ZToxNXB4O2NvbG9yOiM5OTl9bGFiZWwsaW5wdXQsYnV0
dG9uLHNlbGVjdCx0ZXh0YXJlYXtmb250LXNpemU6MTRweDtmb250LXdlaWdodDpub3JtYWw7bGluZS1o
ZWlnaHQ6MjBweH1pbnB1dCxidXR0b24sc2VsZWN0LHRleHRhcmVhe2ZvbnQtZmFtaWx5OiJIZWx2ZXRp
Y2EgTmV1ZSIsSGVsdmV0aWNhLEFyaWFsLHNhbnMtc2VyaWZ9bGFiZWx7ZGlzcGxheTpibG9jazttYXJn
aW4tYm90dG9tOjVweH1zZWxlY3QsdGV4dGFyZWEsaW5wdXRbdHlwZT0idGV4dCJdLGlucHV0W3R5cGU9
InBhc3N3b3JkIl0saW5wdXRbdHlwZT0iZGF0ZXRpbWUiXSxpbnB1dFt0eXBlPSJkYXRldGltZS1sb2Nh
bCJdLGlucHV0W3R5cGU9ImRhdGUiXSxpbnB1dFt0eXBlPSJtb250aCJdLGlucHV0W3R5cGU9InRpbWUi
XSxpbnB1dFt0eXBlPSJ3ZWVrIl0saW5wdXRbdHlwZT0ibnVtYmVyIl0saW5wdXRbdHlwZT0iZW1haWwi
XSxpbnB1dFt0eXBlPSJ1cmwiXSxpbnB1dFt0eXBlPSJzZWFyY2giXSxpbnB1dFt0eXBlPSJ0ZWwiXSxp
bnB1dFt0eXBlPSJjb2xvciJdLC51bmVkaXRhYmxlLWlucHV0e2Rpc3BsYXk6aW5saW5lLWJsb2NrO2hl
aWdodDoyMHB4O3BhZGRpbmc6NHB4IDZweDttYXJnaW4tYm90dG9tOjEwcHg7Zm9udC1zaXplOjE0cHg7
bGluZS1oZWlnaHQ6MjBweDtjb2xvcjojNTU1O3ZlcnRpY2FsLWFsaWduOm1pZGRsZTstd2Via2l0LWJv
cmRlci1yYWRpdXM6NHB4Oy1tb3otYm9yZGVyLXJhZGl1czo0cHg7Ym9yZGVyLXJhZGl1czo0cHh9aW5w
dXQsdGV4dGFyZWEsLnVuZWRpdGFibGUtaW5wdXR7d2lkdGg6MjA2cHh9dGV4dGFyZWF7aGVpZ2h0OmF1
dG99dGV4dGFyZWEsaW5wdXRbdHlwZT0idGV4dCJdLGlucHV0W3R5cGU9InBhc3N3b3JkIl0saW5wdXRb
dHlwZT0iZGF0ZXRpbWUiXSxpbnB1dFt0eXBlPSJkYXRldGltZS1sb2NhbCJdLGlucHV0W3R5cGU9ImRh
dGUiXSxpbnB1dFt0eXBlPSJtb250aCJdLGlucHV0W3R5cGU9InRpbWUiXSxpbnB1dFt0eXBlPSJ3ZWVr
Il0saW5wdXRbdHlwZT0ibnVtYmVyIl0saW5wdXRbdHlwZT0iZW1haWwiXSxpbnB1dFt0eXBlPSJ1cmwi
XSxpbnB1dFt0eXBlPSJzZWFyY2giXSxpbnB1dFt0eXBlPSJ0ZWwiXSxpbnB1dFt0eXBlPSJjb2xvciJd
LC51bmVkaXRhYmxlLWlucHV0e2JhY2tncm91bmQtY29sb3I6I2ZmZjtib3JkZXI6MXB4IHNvbGlkICNj
Y2M7LXdlYmtpdC1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1KTstbW96
LWJveC1zaGFkb3c6aW5zZXQgMCAxcHggMXB4IHJnYmEoMCwwLDAsMC4wNzUpO2JveC1zaGFkb3c6aW5z
ZXQgMCAxcHggMXB4IHJnYmEoMCwwLDAsMC4wNzUpOy13ZWJraXQtdHJhbnNpdGlvbjpib3JkZXIgbGlu
ZWFyIC4ycyxib3gtc2hhZG93IGxpbmVhciAuMnM7LW1vei10cmFuc2l0aW9uOmJvcmRlciBsaW5lYXIg
LjJzLGJveC1zaGFkb3cgbGluZWFyIC4yczstby10cmFuc2l0aW9uOmJvcmRlciBsaW5lYXIgLjJzLGJv
eC1zaGFkb3cgbGluZWFyIC4yczt0cmFuc2l0aW9uOmJvcmRlciBsaW5lYXIgLjJzLGJveC1zaGFkb3cg
bGluZWFyIC4yc310ZXh0YXJlYTpmb2N1cyxpbnB1dFt0eXBlPSJ0ZXh0Il06Zm9jdXMsaW5wdXRbdHlw
ZT0icGFzc3dvcmQiXTpmb2N1cyxpbnB1dFt0eXBlPSJkYXRldGltZSJdOmZvY3VzLGlucHV0W3R5cGU9
ImRhdGV0aW1lLWxvY2FsIl06Zm9jdXMsaW5wdXRbdHlwZT0iZGF0ZSJdOmZvY3VzLGlucHV0W3R5cGU9
Im1vbnRoIl06Zm9jdXMsaW5wdXRbdHlwZT0idGltZSJdOmZvY3VzLGlucHV0W3R5cGU9IndlZWsiXTpm
b2N1cyxpbnB1dFt0eXBlPSJudW1iZXIiXTpmb2N1cyxpbnB1dFt0eXBlPSJlbWFpbCJdOmZvY3VzLGlu
cHV0W3R5cGU9InVybCJdOmZvY3VzLGlucHV0W3R5cGU9InNlYXJjaCJdOmZvY3VzLGlucHV0W3R5cGU9
InRlbCJdOmZvY3VzLGlucHV0W3R5cGU9ImNvbG9yIl06Zm9jdXMsLnVuZWRpdGFibGUtaW5wdXQ6Zm9j
dXN7Ym9yZGVyLWNvbG9yOnJnYmEoODIsMTY4LDIzNiwwLjgpO291dGxpbmU6MDtvdXRsaW5lOnRoaW4g
ZG90dGVkIFw5Oy13ZWJraXQtYm94LXNoYWRvdzppbnNldCAwIDFweCAxcHggcmdiYSgwLDAsMCwwLjA3
NSksMCAwIDhweCByZ2JhKDgyLDE2OCwyMzYsMC42KTstbW96LWJveC1zaGFkb3c6aW5zZXQgMCAxcHgg
MXB4IHJnYmEoMCwwLDAsMC4wNzUpLDAgMCA4cHggcmdiYSg4MiwxNjgsMjM2LDAuNik7Ym94LXNoYWRv
dzppbnNldCAwIDFweCAxcHggcmdiYSgwLDAsMCwwLjA3NSksMCAwIDhweCByZ2JhKDgyLDE2OCwyMzYs
MC42KX1pbnB1dFt0eXBlPSJyYWRpbyJdLGlucHV0W3R5cGU9ImNoZWNrYm94Il17bWFyZ2luOjRweCAw
IDA7bWFyZ2luLXRvcDoxcHggXDk7Km1hcmdpbi10b3A6MDtsaW5lLWhlaWdodDpub3JtYWx9aW5wdXRb
dHlwZT0iZmlsZSJdLGlucHV0W3R5cGU9ImltYWdlIl0saW5wdXRbdHlwZT0ic3VibWl0Il0saW5wdXRb
dHlwZT0icmVzZXQiXSxpbnB1dFt0eXBlPSJidXR0b24iXSxpbnB1dFt0eXBlPSJyYWRpbyJdLGlucHV0
W3R5cGU9ImNoZWNrYm94Il17d2lkdGg6YXV0b31zZWxlY3QsaW5wdXRbdHlwZT0iZmlsZSJde2hlaWdo
dDozMHB4OyptYXJnaW4tdG9wOjRweDtsaW5lLWhlaWdodDozMHB4fXNlbGVjdHt3aWR0aDoyMjBweDti
YWNrZ3JvdW5kLWNvbG9yOiNmZmY7Ym9yZGVyOjFweCBzb2xpZCAjY2NjfXNlbGVjdFttdWx0aXBsZV0s
c2VsZWN0W3NpemVde2hlaWdodDphdXRvfXNlbGVjdDpmb2N1cyxpbnB1dFt0eXBlPSJmaWxlIl06Zm9j
dXMsaW5wdXRbdHlwZT0icmFkaW8iXTpmb2N1cyxpbnB1dFt0eXBlPSJjaGVja2JveCJdOmZvY3Vze291
dGxpbmU6dGhpbiBkb3R0ZWQgIzMzMztvdXRsaW5lOjVweCBhdXRvIC13ZWJraXQtZm9jdXMtcmluZy1j
b2xvcjtvdXRsaW5lLW9mZnNldDotMnB4fS51bmVkaXRhYmxlLWlucHV0LC51bmVkaXRhYmxlLXRleHRh
cmVhe2NvbG9yOiM5OTk7Y3Vyc29yOm5vdC1hbGxvd2VkO2JhY2tncm91bmQtY29sb3I6I2ZjZmNmYzti
b3JkZXItY29sb3I6I2NjYzstd2Via2l0LWJveC1zaGFkb3c6aW5zZXQgMCAxcHggMnB4IHJnYmEoMCww
LDAsMC4wMjUpOy1tb3otYm94LXNoYWRvdzppbnNldCAwIDFweCAycHggcmdiYSgwLDAsMCwwLjAyNSk7
Ym94LXNoYWRvdzppbnNldCAwIDFweCAycHggcmdiYSgwLDAsMCwwLjAyNSl9LnVuZWRpdGFibGUtaW5w
dXR7b3ZlcmZsb3c6aGlkZGVuO3doaXRlLXNwYWNlOm5vd3JhcH0udW5lZGl0YWJsZS10ZXh0YXJlYXt3
aWR0aDphdXRvO2hlaWdodDphdXRvfWlucHV0Oi1tb3otcGxhY2Vob2xkZXIsdGV4dGFyZWE6LW1vei1w
bGFjZWhvbGRlcntjb2xvcjojOTk5fWlucHV0Oi1tcy1pbnB1dC1wbGFjZWhvbGRlcix0ZXh0YXJlYTot
bXMtaW5wdXQtcGxhY2Vob2xkZXJ7Y29sb3I6Izk5OX1pbnB1dDo6LXdlYmtpdC1pbnB1dC1wbGFjZWhv
bGRlcix0ZXh0YXJlYTo6LXdlYmtpdC1pbnB1dC1wbGFjZWhvbGRlcntjb2xvcjojOTk5fS5yYWRpbywu
Y2hlY2tib3h7bWluLWhlaWdodDoyMHB4O3BhZGRpbmctbGVmdDoyMHB4fS5yYWRpbyBpbnB1dFt0eXBl
PSJyYWRpbyJdLC5jaGVja2JveCBpbnB1dFt0eXBlPSJjaGVja2JveCJde2Zsb2F0OmxlZnQ7bWFyZ2lu
LWxlZnQ6LTIwcHh9LmNvbnRyb2xzPi5yYWRpbzpmaXJzdC1jaGlsZCwuY29udHJvbHM+LmNoZWNrYm94
OmZpcnN0LWNoaWxke3BhZGRpbmctdG9wOjVweH0ucmFkaW8uaW5saW5lLC5jaGVja2JveC5pbmxpbmV7
ZGlzcGxheTppbmxpbmUtYmxvY2s7cGFkZGluZy10b3A6NXB4O21hcmdpbi1ib3R0b206MDt2ZXJ0aWNh
bC1hbGlnbjptaWRkbGV9LnJhZGlvLmlubGluZSsucmFkaW8uaW5saW5lLC5jaGVja2JveC5pbmxpbmUr
LmNoZWNrYm94LmlubGluZXttYXJnaW4tbGVmdDoxMHB4fS5pbnB1dC1taW5pe3dpZHRoOjYwcHh9Lmlu
cHV0LXNtYWxse3dpZHRoOjkwcHh9LmlucHV0LW1lZGl1bXt3aWR0aDoxNTBweH0uaW5wdXQtbGFyZ2V7
d2lkdGg6MjEwcHh9LmlucHV0LXhsYXJnZXt3aWR0aDoyNzBweH0uaW5wdXQteHhsYXJnZXt3aWR0aDo1
MzBweH1pbnB1dFtjbGFzcyo9InNwYW4iXSxzZWxlY3RbY2xhc3MqPSJzcGFuIl0sdGV4dGFyZWFbY2xh
c3MqPSJzcGFuIl0sLnVuZWRpdGFibGUtaW5wdXRbY2xhc3MqPSJzcGFuIl0sLnJvdy1mbHVpZCBpbnB1
dFtjbGFzcyo9InNwYW4iXSwucm93LWZsdWlkIHNlbGVjdFtjbGFzcyo9InNwYW4iXSwucm93LWZsdWlk
IHRleHRhcmVhW2NsYXNzKj0ic3BhbiJdLC5yb3ctZmx1aWQgLnVuZWRpdGFibGUtaW5wdXRbY2xhc3Mq
PSJzcGFuIl17ZmxvYXQ6bm9uZTttYXJnaW4tbGVmdDowfS5pbnB1dC1hcHBlbmQgaW5wdXRbY2xhc3Mq
PSJzcGFuIl0sLmlucHV0LWFwcGVuZCAudW5lZGl0YWJsZS1pbnB1dFtjbGFzcyo9InNwYW4iXSwuaW5w
dXQtcHJlcGVuZCBpbnB1dFtjbGFzcyo9InNwYW4iXSwuaW5wdXQtcHJlcGVuZCAudW5lZGl0YWJsZS1p
bnB1dFtjbGFzcyo9InNwYW4iXSwucm93LWZsdWlkIGlucHV0W2NsYXNzKj0ic3BhbiJdLC5yb3ctZmx1
aWQgc2VsZWN0W2NsYXNzKj0ic3BhbiJdLC5yb3ctZmx1aWQgdGV4dGFyZWFbY2xhc3MqPSJzcGFuIl0s
LnJvdy1mbHVpZCAudW5lZGl0YWJsZS1pbnB1dFtjbGFzcyo9InNwYW4iXSwucm93LWZsdWlkIC5pbnB1
dC1wcmVwZW5kIFtjbGFzcyo9InNwYW4iXSwucm93LWZsdWlkIC5pbnB1dC1hcHBlbmQgW2NsYXNzKj0i
c3BhbiJde2Rpc3BsYXk6aW5saW5lLWJsb2NrfWlucHV0LHRleHRhcmVhLC51bmVkaXRhYmxlLWlucHV0
e21hcmdpbi1sZWZ0OjB9LmNvbnRyb2xzLXJvdyBbY2xhc3MqPSJzcGFuIl0rW2NsYXNzKj0ic3BhbiJd
e21hcmdpbi1sZWZ0OjIwcHh9aW5wdXQuc3BhbjEyLHRleHRhcmVhLnNwYW4xMiwudW5lZGl0YWJsZS1p
bnB1dC5zcGFuMTJ7d2lkdGg6OTI2cHh9aW5wdXQuc3BhbjExLHRleHRhcmVhLnNwYW4xMSwudW5lZGl0
YWJsZS1pbnB1dC5zcGFuMTF7d2lkdGg6ODQ2cHh9aW5wdXQuc3BhbjEwLHRleHRhcmVhLnNwYW4xMCwu
dW5lZGl0YWJsZS1pbnB1dC5zcGFuMTB7d2lkdGg6NzY2cHh9aW5wdXQuc3BhbjksdGV4dGFyZWEuc3Bh
bjksLnVuZWRpdGFibGUtaW5wdXQuc3Bhbjl7d2lkdGg6Njg2cHh9aW5wdXQuc3BhbjgsdGV4dGFyZWEu
c3BhbjgsLnVuZWRpdGFibGUtaW5wdXQuc3Bhbjh7d2lkdGg6NjA2cHh9aW5wdXQuc3BhbjcsdGV4dGFy
ZWEuc3BhbjcsLnVuZWRpdGFibGUtaW5wdXQuc3Bhbjd7d2lkdGg6NTI2cHh9aW5wdXQuc3BhbjYsdGV4
dGFyZWEuc3BhbjYsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjZ7d2lkdGg6NDQ2cHh9aW5wdXQuc3BhbjUs
dGV4dGFyZWEuc3BhbjUsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjV7d2lkdGg6MzY2cHh9aW5wdXQuc3Bh
bjQsdGV4dGFyZWEuc3BhbjQsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjR7d2lkdGg6Mjg2cHh9aW5wdXQu
c3BhbjMsdGV4dGFyZWEuc3BhbjMsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjN7d2lkdGg6MjA2cHh9aW5w
dXQuc3BhbjIsdGV4dGFyZWEuc3BhbjIsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjJ7d2lkdGg6MTI2cHh9
aW5wdXQuc3BhbjEsdGV4dGFyZWEuc3BhbjEsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjF7d2lkdGg6NDZw
eH0uY29udHJvbHMtcm93eyp6b29tOjF9LmNvbnRyb2xzLXJvdzpiZWZvcmUsLmNvbnRyb2xzLXJvdzph
ZnRlcntkaXNwbGF5OnRhYmxlO2xpbmUtaGVpZ2h0OjA7Y29udGVudDoiIn0uY29udHJvbHMtcm93OmFm
dGVye2NsZWFyOmJvdGh9LmNvbnRyb2xzLXJvdyBbY2xhc3MqPSJzcGFuIl0sLnJvdy1mbHVpZCAuY29u
dHJvbHMtcm93IFtjbGFzcyo9InNwYW4iXXtmbG9hdDpsZWZ0fS5jb250cm9scy1yb3cgLmNoZWNrYm94
W2NsYXNzKj0ic3BhbiJdLC5jb250cm9scy1yb3cgLnJhZGlvW2NsYXNzKj0ic3BhbiJde3BhZGRpbmct
dG9wOjVweH1pbnB1dFtkaXNhYmxlZF0sc2VsZWN0W2Rpc2FibGVkXSx0ZXh0YXJlYVtkaXNhYmxlZF0s
aW5wdXRbcmVhZG9ubHldLHNlbGVjdFtyZWFkb25seV0sdGV4dGFyZWFbcmVhZG9ubHlde2N1cnNvcjpu
b3QtYWxsb3dlZDtiYWNrZ3JvdW5kLWNvbG9yOiNlZWV9aW5wdXRbdHlwZT0icmFkaW8iXVtkaXNhYmxl
ZF0saW5wdXRbdHlwZT0iY2hlY2tib3giXVtkaXNhYmxlZF0saW5wdXRbdHlwZT0icmFkaW8iXVtyZWFk
b25seV0saW5wdXRbdHlwZT0iY2hlY2tib3giXVtyZWFkb25seV17YmFja2dyb3VuZC1jb2xvcjp0cmFu
c3BhcmVudH0uY29udHJvbC1ncm91cC53YXJuaW5nIC5jb250cm9sLWxhYmVsLC5jb250cm9sLWdyb3Vw
Lndhcm5pbmcgLmhlbHAtYmxvY2ssLmNvbnRyb2wtZ3JvdXAud2FybmluZyAuaGVscC1pbmxpbmV7Y29s
b3I6I2MwOTg1M30uY29udHJvbC1ncm91cC53YXJuaW5nIC5jaGVja2JveCwuY29udHJvbC1ncm91cC53
YXJuaW5nIC5yYWRpbywuY29udHJvbC1ncm91cC53YXJuaW5nIGlucHV0LC5jb250cm9sLWdyb3VwLndh
cm5pbmcgc2VsZWN0LC5jb250cm9sLWdyb3VwLndhcm5pbmcgdGV4dGFyZWF7Y29sb3I6I2MwOTg1M30u
Y29udHJvbC1ncm91cC53YXJuaW5nIGlucHV0LC5jb250cm9sLWdyb3VwLndhcm5pbmcgc2VsZWN0LC5j
b250cm9sLWdyb3VwLndhcm5pbmcgdGV4dGFyZWF7Ym9yZGVyLWNvbG9yOiNjMDk4NTM7LXdlYmtpdC1i
b3gtc2hhZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1KTstbW96LWJveC1zaGFkb3c6
aW5zZXQgMCAxcHggMXB4IHJnYmEoMCwwLDAsMC4wNzUpO2JveC1zaGFkb3c6aW5zZXQgMCAxcHggMXB4
IHJnYmEoMCwwLDAsMC4wNzUpfS5jb250cm9sLWdyb3VwLndhcm5pbmcgaW5wdXQ6Zm9jdXMsLmNvbnRy
b2wtZ3JvdXAud2FybmluZyBzZWxlY3Q6Zm9jdXMsLmNvbnRyb2wtZ3JvdXAud2FybmluZyB0ZXh0YXJl
YTpmb2N1c3tib3JkZXItY29sb3I6I2E0N2UzYzstd2Via2l0LWJveC1zaGFkb3c6aW5zZXQgMCAxcHgg
MXB4IHJnYmEoMCwwLDAsMC4wNzUpLDAgMCA2cHggI2RiYzU5ZTstbW96LWJveC1zaGFkb3c6aW5zZXQg
MCAxcHggMXB4IHJnYmEoMCwwLDAsMC4wNzUpLDAgMCA2cHggI2RiYzU5ZTtib3gtc2hhZG93Omluc2V0
IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1KSwwIDAgNnB4ICNkYmM1OWV9LmNvbnRyb2wtZ3JvdXAu
d2FybmluZyAuaW5wdXQtcHJlcGVuZCAuYWRkLW9uLC5jb250cm9sLWdyb3VwLndhcm5pbmcgLmlucHV0
LWFwcGVuZCAuYWRkLW9ue2NvbG9yOiNjMDk4NTM7YmFja2dyb3VuZC1jb2xvcjojZmNmOGUzO2JvcmRl
ci1jb2xvcjojYzA5ODUzfS5jb250cm9sLWdyb3VwLmVycm9yIC5jb250cm9sLWxhYmVsLC5jb250cm9s
LWdyb3VwLmVycm9yIC5oZWxwLWJsb2NrLC5jb250cm9sLWdyb3VwLmVycm9yIC5oZWxwLWlubGluZXtj
b2xvcjojYjk0YTQ4fS5jb250cm9sLWdyb3VwLmVycm9yIC5jaGVja2JveCwuY29udHJvbC1ncm91cC5l
cnJvciAucmFkaW8sLmNvbnRyb2wtZ3JvdXAuZXJyb3IgaW5wdXQsLmNvbnRyb2wtZ3JvdXAuZXJyb3Ig
c2VsZWN0LC5jb250cm9sLWdyb3VwLmVycm9yIHRleHRhcmVhe2NvbG9yOiNiOTRhNDh9LmNvbnRyb2wt
Z3JvdXAuZXJyb3IgaW5wdXQsLmNvbnRyb2wtZ3JvdXAuZXJyb3Igc2VsZWN0LC5jb250cm9sLWdyb3Vw
LmVycm9yIHRleHRhcmVhe2JvcmRlci1jb2xvcjojYjk0YTQ4Oy13ZWJraXQtYm94LXNoYWRvdzppbnNl
dCAwIDFweCAxcHggcmdiYSgwLDAsMCwwLjA3NSk7LW1vei1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDFw
eCByZ2JhKDAsMCwwLDAuMDc1KTtib3gtc2hhZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAu
MDc1KX0uY29udHJvbC1ncm91cC5lcnJvciBpbnB1dDpmb2N1cywuY29udHJvbC1ncm91cC5lcnJvciBz
ZWxlY3Q6Zm9jdXMsLmNvbnRyb2wtZ3JvdXAuZXJyb3IgdGV4dGFyZWE6Zm9jdXN7Ym9yZGVyLWNvbG9y
OiM5NTNiMzk7LXdlYmtpdC1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1
KSwwIDAgNnB4ICNkNTkzOTI7LW1vei1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCww
LDAuMDc1KSwwIDAgNnB4ICNkNTkzOTI7Ym94LXNoYWRvdzppbnNldCAwIDFweCAxcHggcmdiYSgwLDAs
MCwwLjA3NSksMCAwIDZweCAjZDU5MzkyfS5jb250cm9sLWdyb3VwLmVycm9yIC5pbnB1dC1wcmVwZW5k
IC5hZGQtb24sLmNvbnRyb2wtZ3JvdXAuZXJyb3IgLmlucHV0LWFwcGVuZCAuYWRkLW9ue2NvbG9yOiNi
OTRhNDg7YmFja2dyb3VuZC1jb2xvcjojZjJkZWRlO2JvcmRlci1jb2xvcjojYjk0YTQ4fS5jb250cm9s
LWdyb3VwLnN1Y2Nlc3MgLmNvbnRyb2wtbGFiZWwsLmNvbnRyb2wtZ3JvdXAuc3VjY2VzcyAuaGVscC1i
bG9jaywuY29udHJvbC1ncm91cC5zdWNjZXNzIC5oZWxwLWlubGluZXtjb2xvcjojNDY4ODQ3fS5jb250
cm9sLWdyb3VwLnN1Y2Nlc3MgLmNoZWNrYm94LC5jb250cm9sLWdyb3VwLnN1Y2Nlc3MgLnJhZGlvLC5j
b250cm9sLWdyb3VwLnN1Y2Nlc3MgaW5wdXQsLmNvbnRyb2wtZ3JvdXAuc3VjY2VzcyBzZWxlY3QsLmNv
bnRyb2wtZ3JvdXAuc3VjY2VzcyB0ZXh0YXJlYXtjb2xvcjojNDY4ODQ3fS5jb250cm9sLWdyb3VwLnN1
Y2Nlc3MgaW5wdXQsLmNvbnRyb2wtZ3JvdXAuc3VjY2VzcyBzZWxlY3QsLmNvbnRyb2wtZ3JvdXAuc3Vj
Y2VzcyB0ZXh0YXJlYXtib3JkZXItY29sb3I6IzQ2ODg0Nzstd2Via2l0LWJveC1zaGFkb3c6aW5zZXQg
MCAxcHggMXB4IHJnYmEoMCwwLDAsMC4wNzUpOy1tb3otYm94LXNoYWRvdzppbnNldCAwIDFweCAxcHgg
cmdiYSgwLDAsMCwwLjA3NSk7Ym94LXNoYWRvdzppbnNldCAwIDFweCAxcHggcmdiYSgwLDAsMCwwLjA3
NSl9LmNvbnRyb2wtZ3JvdXAuc3VjY2VzcyBpbnB1dDpmb2N1cywuY29udHJvbC1ncm91cC5zdWNjZXNz
IHNlbGVjdDpmb2N1cywuY29udHJvbC1ncm91cC5zdWNjZXNzIHRleHRhcmVhOmZvY3Vze2JvcmRlci1j
b2xvcjojMzU2NjM1Oy13ZWJraXQtYm94LXNoYWRvdzppbnNldCAwIDFweCAxcHggcmdiYSgwLDAsMCww
LjA3NSksMCAwIDZweCAjN2FiYTdiOy1tb3otYm94LXNoYWRvdzppbnNldCAwIDFweCAxcHggcmdiYSgw
LDAsMCwwLjA3NSksMCAwIDZweCAjN2FiYTdiO2JveC1zaGFkb3c6aW5zZXQgMCAxcHggMXB4IHJnYmEo
MCwwLDAsMC4wNzUpLDAgMCA2cHggIzdhYmE3Yn0uY29udHJvbC1ncm91cC5zdWNjZXNzIC5pbnB1dC1w
cmVwZW5kIC5hZGQtb24sLmNvbnRyb2wtZ3JvdXAuc3VjY2VzcyAuaW5wdXQtYXBwZW5kIC5hZGQtb257
Y29sb3I6IzQ2ODg0NztiYWNrZ3JvdW5kLWNvbG9yOiNkZmYwZDg7Ym9yZGVyLWNvbG9yOiM0Njg4NDd9
LmNvbnRyb2wtZ3JvdXAuaW5mbyAuY29udHJvbC1sYWJlbCwuY29udHJvbC1ncm91cC5pbmZvIC5oZWxw
LWJsb2NrLC5jb250cm9sLWdyb3VwLmluZm8gLmhlbHAtaW5saW5le2NvbG9yOiMzYTg3YWR9LmNvbnRy
b2wtZ3JvdXAuaW5mbyAuY2hlY2tib3gsLmNvbnRyb2wtZ3JvdXAuaW5mbyAucmFkaW8sLmNvbnRyb2wt
Z3JvdXAuaW5mbyBpbnB1dCwuY29udHJvbC1ncm91cC5pbmZvIHNlbGVjdCwuY29udHJvbC1ncm91cC5p
bmZvIHRleHRhcmVhe2NvbG9yOiMzYTg3YWR9LmNvbnRyb2wtZ3JvdXAuaW5mbyBpbnB1dCwuY29udHJv
bC1ncm91cC5pbmZvIHNlbGVjdCwuY29udHJvbC1ncm91cC5pbmZvIHRleHRhcmVhe2JvcmRlci1jb2xv
cjojM2E4N2FkOy13ZWJraXQtYm94LXNoYWRvdzppbnNldCAwIDFweCAxcHggcmdiYSgwLDAsMCwwLjA3
NSk7LW1vei1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1KTtib3gtc2hh
ZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1KX0uY29udHJvbC1ncm91cC5pbmZvIGlu
cHV0OmZvY3VzLC5jb250cm9sLWdyb3VwLmluZm8gc2VsZWN0OmZvY3VzLC5jb250cm9sLWdyb3VwLmlu
Zm8gdGV4dGFyZWE6Zm9jdXN7Ym9yZGVyLWNvbG9yOiMyZDY5ODc7LXdlYmtpdC1ib3gtc2hhZG93Omlu
c2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1KSwwIDAgNnB4ICM3YWI1ZDM7LW1vei1ib3gtc2hh
ZG93Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDc1KSwwIDAgNnB4ICM3YWI1ZDM7Ym94LXNo
YWRvdzppbnNldCAwIDFweCAxcHggcmdiYSgwLDAsMCwwLjA3NSksMCAwIDZweCAjN2FiNWQzfS5jb250
cm9sLWdyb3VwLmluZm8gLmlucHV0LXByZXBlbmQgLmFkZC1vbiwuY29udHJvbC1ncm91cC5pbmZvIC5p
bnB1dC1hcHBlbmQgLmFkZC1vbntjb2xvcjojM2E4N2FkO2JhY2tncm91bmQtY29sb3I6I2Q5ZWRmNzti
b3JkZXItY29sb3I6IzNhODdhZH1pbnB1dDpmb2N1czppbnZhbGlkLHRleHRhcmVhOmZvY3VzOmludmFs
aWQsc2VsZWN0OmZvY3VzOmludmFsaWR7Y29sb3I6I2I5NGE0ODtib3JkZXItY29sb3I6I2VlNWY1Yn1p
bnB1dDpmb2N1czppbnZhbGlkOmZvY3VzLHRleHRhcmVhOmZvY3VzOmludmFsaWQ6Zm9jdXMsc2VsZWN0
OmZvY3VzOmludmFsaWQ6Zm9jdXN7Ym9yZGVyLWNvbG9yOiNlOTMyMmQ7LXdlYmtpdC1ib3gtc2hhZG93
OjAgMCA2cHggI2Y4YjliNzstbW96LWJveC1zaGFkb3c6MCAwIDZweCAjZjhiOWI3O2JveC1zaGFkb3c6
MCAwIDZweCAjZjhiOWI3fS5mb3JtLWFjdGlvbnN7cGFkZGluZzoxOXB4IDIwcHggMjBweDttYXJnaW4t
dG9wOjIwcHg7bWFyZ2luLWJvdHRvbToyMHB4O2JhY2tncm91bmQtY29sb3I6I2Y1ZjVmNTtib3JkZXIt
dG9wOjFweCBzb2xpZCAjZTVlNWU1Oyp6b29tOjF9LmZvcm0tYWN0aW9uczpiZWZvcmUsLmZvcm0tYWN0
aW9uczphZnRlcntkaXNwbGF5OnRhYmxlO2xpbmUtaGVpZ2h0OjA7Y29udGVudDoiIn0uZm9ybS1hY3Rp
b25zOmFmdGVye2NsZWFyOmJvdGh9LmhlbHAtYmxvY2ssLmhlbHAtaW5saW5le2NvbG9yOiM1OTU5NTl9
LmhlbHAtYmxvY2t7ZGlzcGxheTpibG9jazttYXJnaW4tYm90dG9tOjEwcHh9LmhlbHAtaW5saW5le2Rp
c3BsYXk6aW5saW5lLWJsb2NrOypkaXNwbGF5OmlubGluZTtwYWRkaW5nLWxlZnQ6NXB4O3ZlcnRpY2Fs
LWFsaWduOm1pZGRsZTsqem9vbToxfS5pbnB1dC1hcHBlbmQsLmlucHV0LXByZXBlbmR7ZGlzcGxheTpp
bmxpbmUtYmxvY2s7bWFyZ2luLWJvdHRvbToxMHB4O2ZvbnQtc2l6ZTowO3doaXRlLXNwYWNlOm5vd3Jh
cDt2ZXJ0aWNhbC1hbGlnbjptaWRkbGV9LmlucHV0LWFwcGVuZCBpbnB1dCwuaW5wdXQtcHJlcGVuZCBp
bnB1dCwuaW5wdXQtYXBwZW5kIHNlbGVjdCwuaW5wdXQtcHJlcGVuZCBzZWxlY3QsLmlucHV0LWFwcGVu
ZCAudW5lZGl0YWJsZS1pbnB1dCwuaW5wdXQtcHJlcGVuZCAudW5lZGl0YWJsZS1pbnB1dCwuaW5wdXQt
YXBwZW5kIC5kcm9wZG93bi1tZW51LC5pbnB1dC1wcmVwZW5kIC5kcm9wZG93bi1tZW51LC5pbnB1dC1h
cHBlbmQgLnBvcG92ZXIsLmlucHV0LXByZXBlbmQgLnBvcG92ZXJ7Zm9udC1zaXplOjE0cHh9LmlucHV0
LWFwcGVuZCBpbnB1dCwuaW5wdXQtcHJlcGVuZCBpbnB1dCwuaW5wdXQtYXBwZW5kIHNlbGVjdCwuaW5w
dXQtcHJlcGVuZCBzZWxlY3QsLmlucHV0LWFwcGVuZCAudW5lZGl0YWJsZS1pbnB1dCwuaW5wdXQtcHJl
cGVuZCAudW5lZGl0YWJsZS1pbnB1dHtwb3NpdGlvbjpyZWxhdGl2ZTttYXJnaW4tYm90dG9tOjA7Km1h
cmdpbi1sZWZ0OjA7dmVydGljYWwtYWxpZ246dG9wOy13ZWJraXQtYm9yZGVyLXJhZGl1czowIDRweCA0
cHggMDstbW96LWJvcmRlci1yYWRpdXM6MCA0cHggNHB4IDA7Ym9yZGVyLXJhZGl1czowIDRweCA0cHgg
MH0uaW5wdXQtYXBwZW5kIGlucHV0OmZvY3VzLC5pbnB1dC1wcmVwZW5kIGlucHV0OmZvY3VzLC5pbnB1
dC1hcHBlbmQgc2VsZWN0OmZvY3VzLC5pbnB1dC1wcmVwZW5kIHNlbGVjdDpmb2N1cywuaW5wdXQtYXBw
ZW5kIC51bmVkaXRhYmxlLWlucHV0OmZvY3VzLC5pbnB1dC1wcmVwZW5kIC51bmVkaXRhYmxlLWlucHV0
OmZvY3Vze3otaW5kZXg6Mn0uaW5wdXQtYXBwZW5kIC5hZGQtb24sLmlucHV0LXByZXBlbmQgLmFkZC1v
bntkaXNwbGF5OmlubGluZS1ibG9jazt3aWR0aDphdXRvO2hlaWdodDoyMHB4O21pbi13aWR0aDoxNnB4
O3BhZGRpbmc6NHB4IDVweDtmb250LXNpemU6MTRweDtmb250LXdlaWdodDpub3JtYWw7bGluZS1oZWln
aHQ6MjBweDt0ZXh0LWFsaWduOmNlbnRlcjt0ZXh0LXNoYWRvdzowIDFweCAwICNmZmY7YmFja2dyb3Vu
ZC1jb2xvcjojZWVlO2JvcmRlcjoxcHggc29saWQgI2NjY30uaW5wdXQtYXBwZW5kIC5hZGQtb24sLmlu
cHV0LXByZXBlbmQgLmFkZC1vbiwuaW5wdXQtYXBwZW5kIC5idG4sLmlucHV0LXByZXBlbmQgLmJ0biwu
aW5wdXQtYXBwZW5kIC5idG4tZ3JvdXA+LmRyb3Bkb3duLXRvZ2dsZSwuaW5wdXQtcHJlcGVuZCAuYnRu
LWdyb3VwPi5kcm9wZG93bi10b2dnbGV7dmVydGljYWwtYWxpZ246dG9wOy13ZWJraXQtYm9yZGVyLXJh
ZGl1czowOy1tb3otYm9yZGVyLXJhZGl1czowO2JvcmRlci1yYWRpdXM6MH0uaW5wdXQtYXBwZW5kIC5h
Y3RpdmUsLmlucHV0LXByZXBlbmQgLmFjdGl2ZXtiYWNrZ3JvdW5kLWNvbG9yOiNhOWRiYTk7Ym9yZGVy
LWNvbG9yOiM0NmE1NDZ9LmlucHV0LXByZXBlbmQgLmFkZC1vbiwuaW5wdXQtcHJlcGVuZCAuYnRue21h
cmdpbi1yaWdodDotMXB4fS5pbnB1dC1wcmVwZW5kIC5hZGQtb246Zmlyc3QtY2hpbGQsLmlucHV0LXBy
ZXBlbmQgLmJ0bjpmaXJzdC1jaGlsZHstd2Via2l0LWJvcmRlci1yYWRpdXM6NHB4IDAgMCA0cHg7LW1v
ei1ib3JkZXItcmFkaXVzOjRweCAwIDAgNHB4O2JvcmRlci1yYWRpdXM6NHB4IDAgMCA0cHh9LmlucHV0
LWFwcGVuZCBpbnB1dCwuaW5wdXQtYXBwZW5kIHNlbGVjdCwuaW5wdXQtYXBwZW5kIC51bmVkaXRhYmxl
LWlucHV0ey13ZWJraXQtYm9yZGVyLXJhZGl1czo0cHggMCAwIDRweDstbW96LWJvcmRlci1yYWRpdXM6
NHB4IDAgMCA0cHg7Ym9yZGVyLXJhZGl1czo0cHggMCAwIDRweH0uaW5wdXQtYXBwZW5kIGlucHV0Ky5i
dG4tZ3JvdXAgLmJ0bjpsYXN0LWNoaWxkLC5pbnB1dC1hcHBlbmQgc2VsZWN0Ky5idG4tZ3JvdXAgLmJ0
bjpsYXN0LWNoaWxkLC5pbnB1dC1hcHBlbmQgLnVuZWRpdGFibGUtaW5wdXQrLmJ0bi1ncm91cCAuYnRu
Omxhc3QtY2hpbGR7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjAgNHB4IDRweCAwOy1tb3otYm9yZGVyLXJh
ZGl1czowIDRweCA0cHggMDtib3JkZXItcmFkaXVzOjAgNHB4IDRweCAwfS5pbnB1dC1hcHBlbmQgLmFk
ZC1vbiwuaW5wdXQtYXBwZW5kIC5idG4sLmlucHV0LWFwcGVuZCAuYnRuLWdyb3Vwe21hcmdpbi1sZWZ0
Oi0xcHh9LmlucHV0LWFwcGVuZCAuYWRkLW9uOmxhc3QtY2hpbGQsLmlucHV0LWFwcGVuZCAuYnRuOmxh
c3QtY2hpbGQsLmlucHV0LWFwcGVuZCAuYnRuLWdyb3VwOmxhc3QtY2hpbGQ+LmRyb3Bkb3duLXRvZ2ds
ZXstd2Via2l0LWJvcmRlci1yYWRpdXM6MCA0cHggNHB4IDA7LW1vei1ib3JkZXItcmFkaXVzOjAgNHB4
IDRweCAwO2JvcmRlci1yYWRpdXM6MCA0cHggNHB4IDB9LmlucHV0LXByZXBlbmQuaW5wdXQtYXBwZW5k
IGlucHV0LC5pbnB1dC1wcmVwZW5kLmlucHV0LWFwcGVuZCBzZWxlY3QsLmlucHV0LXByZXBlbmQuaW5w
dXQtYXBwZW5kIC51bmVkaXRhYmxlLWlucHV0ey13ZWJraXQtYm9yZGVyLXJhZGl1czowOy1tb3otYm9y
ZGVyLXJhZGl1czowO2JvcmRlci1yYWRpdXM6MH0uaW5wdXQtcHJlcGVuZC5pbnB1dC1hcHBlbmQgaW5w
dXQrLmJ0bi1ncm91cCAuYnRuLC5pbnB1dC1wcmVwZW5kLmlucHV0LWFwcGVuZCBzZWxlY3QrLmJ0bi1n
cm91cCAuYnRuLC5pbnB1dC1wcmVwZW5kLmlucHV0LWFwcGVuZCAudW5lZGl0YWJsZS1pbnB1dCsuYnRu
LWdyb3VwIC5idG57LXdlYmtpdC1ib3JkZXItcmFkaXVzOjAgNHB4IDRweCAwOy1tb3otYm9yZGVyLXJh
ZGl1czowIDRweCA0cHggMDtib3JkZXItcmFkaXVzOjAgNHB4IDRweCAwfS5pbnB1dC1wcmVwZW5kLmlu
cHV0LWFwcGVuZCAuYWRkLW9uOmZpcnN0LWNoaWxkLC5pbnB1dC1wcmVwZW5kLmlucHV0LWFwcGVuZCAu
YnRuOmZpcnN0LWNoaWxke21hcmdpbi1yaWdodDotMXB4Oy13ZWJraXQtYm9yZGVyLXJhZGl1czo0cHgg
MCAwIDRweDstbW96LWJvcmRlci1yYWRpdXM6NHB4IDAgMCA0cHg7Ym9yZGVyLXJhZGl1czo0cHggMCAw
IDRweH0uaW5wdXQtcHJlcGVuZC5pbnB1dC1hcHBlbmQgLmFkZC1vbjpsYXN0LWNoaWxkLC5pbnB1dC1w
cmVwZW5kLmlucHV0LWFwcGVuZCAuYnRuOmxhc3QtY2hpbGR7bWFyZ2luLWxlZnQ6LTFweDstd2Via2l0
LWJvcmRlci1yYWRpdXM6MCA0cHggNHB4IDA7LW1vei1ib3JkZXItcmFkaXVzOjAgNHB4IDRweCAwO2Jv
cmRlci1yYWRpdXM6MCA0cHggNHB4IDB9LmlucHV0LXByZXBlbmQuaW5wdXQtYXBwZW5kIC5idG4tZ3Jv
dXA6Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6MH1pbnB1dC5zZWFyY2gtcXVlcnl7cGFkZGluZy1yaWdo
dDoxNHB4O3BhZGRpbmctcmlnaHQ6NHB4IFw5O3BhZGRpbmctbGVmdDoxNHB4O3BhZGRpbmctbGVmdDo0
cHggXDk7bWFyZ2luLWJvdHRvbTowOy13ZWJraXQtYm9yZGVyLXJhZGl1czoxNXB4Oy1tb3otYm9yZGVy
LXJhZGl1czoxNXB4O2JvcmRlci1yYWRpdXM6MTVweH0uZm9ybS1zZWFyY2ggLmlucHV0LWFwcGVuZCAu
c2VhcmNoLXF1ZXJ5LC5mb3JtLXNlYXJjaCAuaW5wdXQtcHJlcGVuZCAuc2VhcmNoLXF1ZXJ5ey13ZWJr
aXQtYm9yZGVyLXJhZGl1czowOy1tb3otYm9yZGVyLXJhZGl1czowO2JvcmRlci1yYWRpdXM6MH0uZm9y
bS1zZWFyY2ggLmlucHV0LWFwcGVuZCAuc2VhcmNoLXF1ZXJ5ey13ZWJraXQtYm9yZGVyLXJhZGl1czox
NHB4IDAgMCAxNHB4Oy1tb3otYm9yZGVyLXJhZGl1czoxNHB4IDAgMCAxNHB4O2JvcmRlci1yYWRpdXM6
MTRweCAwIDAgMTRweH0uZm9ybS1zZWFyY2ggLmlucHV0LWFwcGVuZCAuYnRuey13ZWJraXQtYm9yZGVy
LXJhZGl1czowIDE0cHggMTRweCAwOy1tb3otYm9yZGVyLXJhZGl1czowIDE0cHggMTRweCAwO2JvcmRl
ci1yYWRpdXM6MCAxNHB4IDE0cHggMH0uZm9ybS1zZWFyY2ggLmlucHV0LXByZXBlbmQgLnNlYXJjaC1x
dWVyeXstd2Via2l0LWJvcmRlci1yYWRpdXM6MCAxNHB4IDE0cHggMDstbW96LWJvcmRlci1yYWRpdXM6
MCAxNHB4IDE0cHggMDtib3JkZXItcmFkaXVzOjAgMTRweCAxNHB4IDB9LmZvcm0tc2VhcmNoIC5pbnB1
dC1wcmVwZW5kIC5idG57LXdlYmtpdC1ib3JkZXItcmFkaXVzOjE0cHggMCAwIDE0cHg7LW1vei1ib3Jk
ZXItcmFkaXVzOjE0cHggMCAwIDE0cHg7Ym9yZGVyLXJhZGl1czoxNHB4IDAgMCAxNHB4fS5mb3JtLXNl
YXJjaCBpbnB1dCwuZm9ybS1pbmxpbmUgaW5wdXQsLmZvcm0taG9yaXpvbnRhbCBpbnB1dCwuZm9ybS1z
ZWFyY2ggdGV4dGFyZWEsLmZvcm0taW5saW5lIHRleHRhcmVhLC5mb3JtLWhvcml6b250YWwgdGV4dGFy
ZWEsLmZvcm0tc2VhcmNoIHNlbGVjdCwuZm9ybS1pbmxpbmUgc2VsZWN0LC5mb3JtLWhvcml6b250YWwg
c2VsZWN0LC5mb3JtLXNlYXJjaCAuaGVscC1pbmxpbmUsLmZvcm0taW5saW5lIC5oZWxwLWlubGluZSwu
Zm9ybS1ob3Jpem9udGFsIC5oZWxwLWlubGluZSwuZm9ybS1zZWFyY2ggLnVuZWRpdGFibGUtaW5wdXQs
LmZvcm0taW5saW5lIC51bmVkaXRhYmxlLWlucHV0LC5mb3JtLWhvcml6b250YWwgLnVuZWRpdGFibGUt
aW5wdXQsLmZvcm0tc2VhcmNoIC5pbnB1dC1wcmVwZW5kLC5mb3JtLWlubGluZSAuaW5wdXQtcHJlcGVu
ZCwuZm9ybS1ob3Jpem9udGFsIC5pbnB1dC1wcmVwZW5kLC5mb3JtLXNlYXJjaCAuaW5wdXQtYXBwZW5k
LC5mb3JtLWlubGluZSAuaW5wdXQtYXBwZW5kLC5mb3JtLWhvcml6b250YWwgLmlucHV0LWFwcGVuZHtk
aXNwbGF5OmlubGluZS1ibG9jazsqZGlzcGxheTppbmxpbmU7bWFyZ2luLWJvdHRvbTowO3ZlcnRpY2Fs
LWFsaWduOm1pZGRsZTsqem9vbToxfS5mb3JtLXNlYXJjaCAuaGlkZSwuZm9ybS1pbmxpbmUgLmhpZGUs
LmZvcm0taG9yaXpvbnRhbCAuaGlkZXtkaXNwbGF5Om5vbmV9LmZvcm0tc2VhcmNoIGxhYmVsLC5mb3Jt
LWlubGluZSBsYWJlbCwuZm9ybS1zZWFyY2ggLmJ0bi1ncm91cCwuZm9ybS1pbmxpbmUgLmJ0bi1ncm91
cHtkaXNwbGF5OmlubGluZS1ibG9ja30uZm9ybS1zZWFyY2ggLmlucHV0LWFwcGVuZCwuZm9ybS1pbmxp
bmUgLmlucHV0LWFwcGVuZCwuZm9ybS1zZWFyY2ggLmlucHV0LXByZXBlbmQsLmZvcm0taW5saW5lIC5p
bnB1dC1wcmVwZW5ke21hcmdpbi1ib3R0b206MH0uZm9ybS1zZWFyY2ggLnJhZGlvLC5mb3JtLXNlYXJj
aCAuY2hlY2tib3gsLmZvcm0taW5saW5lIC5yYWRpbywuZm9ybS1pbmxpbmUgLmNoZWNrYm94e3BhZGRp
bmctbGVmdDowO21hcmdpbi1ib3R0b206MDt2ZXJ0aWNhbC1hbGlnbjptaWRkbGV9LmZvcm0tc2VhcmNo
IC5yYWRpbyBpbnB1dFt0eXBlPSJyYWRpbyJdLC5mb3JtLXNlYXJjaCAuY2hlY2tib3ggaW5wdXRbdHlw
ZT0iY2hlY2tib3giXSwuZm9ybS1pbmxpbmUgLnJhZGlvIGlucHV0W3R5cGU9InJhZGlvIl0sLmZvcm0t
aW5saW5lIC5jaGVja2JveCBpbnB1dFt0eXBlPSJjaGVja2JveCJde2Zsb2F0OmxlZnQ7bWFyZ2luLXJp
Z2h0OjNweDttYXJnaW4tbGVmdDowfS5jb250cm9sLWdyb3Vwe21hcmdpbi1ib3R0b206MTBweH1sZWdl
bmQrLmNvbnRyb2wtZ3JvdXB7bWFyZ2luLXRvcDoyMHB4Oy13ZWJraXQtbWFyZ2luLXRvcC1jb2xsYXBz
ZTpzZXBhcmF0ZX0uZm9ybS1ob3Jpem9udGFsIC5jb250cm9sLWdyb3Vwe21hcmdpbi1ib3R0b206MjBw
eDsqem9vbToxfS5mb3JtLWhvcml6b250YWwgLmNvbnRyb2wtZ3JvdXA6YmVmb3JlLC5mb3JtLWhvcml6
b250YWwgLmNvbnRyb2wtZ3JvdXA6YWZ0ZXJ7ZGlzcGxheTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRl
bnQ6IiJ9LmZvcm0taG9yaXpvbnRhbCAuY29udHJvbC1ncm91cDphZnRlcntjbGVhcjpib3RofS5mb3Jt
LWhvcml6b250YWwgLmNvbnRyb2wtbGFiZWx7ZmxvYXQ6bGVmdDt3aWR0aDoxNjBweDtwYWRkaW5nLXRv
cDo1cHg7dGV4dC1hbGlnbjpyaWdodH0uZm9ybS1ob3Jpem9udGFsIC5jb250cm9sc3sqZGlzcGxheTpp
bmxpbmUtYmxvY2s7KnBhZGRpbmctbGVmdDoyMHB4O21hcmdpbi1sZWZ0OjE4MHB4OyptYXJnaW4tbGVm
dDowfS5mb3JtLWhvcml6b250YWwgLmNvbnRyb2xzOmZpcnN0LWNoaWxkeypwYWRkaW5nLWxlZnQ6MTgw
cHh9LmZvcm0taG9yaXpvbnRhbCAuaGVscC1ibG9ja3ttYXJnaW4tYm90dG9tOjB9LmZvcm0taG9yaXpv
bnRhbCBpbnB1dCsuaGVscC1ibG9jaywuZm9ybS1ob3Jpem9udGFsIHNlbGVjdCsuaGVscC1ibG9jaywu
Zm9ybS1ob3Jpem9udGFsIHRleHRhcmVhKy5oZWxwLWJsb2NrLC5mb3JtLWhvcml6b250YWwgLnVuZWRp
dGFibGUtaW5wdXQrLmhlbHAtYmxvY2ssLmZvcm0taG9yaXpvbnRhbCAuaW5wdXQtcHJlcGVuZCsuaGVs
cC1ibG9jaywuZm9ybS1ob3Jpem9udGFsIC5pbnB1dC1hcHBlbmQrLmhlbHAtYmxvY2t7bWFyZ2luLXRv
cDoxMHB4fS5mb3JtLWhvcml6b250YWwgLmZvcm0tYWN0aW9uc3twYWRkaW5nLWxlZnQ6MTgwcHh9dGFi
bGV7bWF4LXdpZHRoOjEwMCU7YmFja2dyb3VuZC1jb2xvcjp0cmFuc3BhcmVudDtib3JkZXItY29sbGFw
c2U6Y29sbGFwc2U7Ym9yZGVyLXNwYWNpbmc6MH0udGFibGV7d2lkdGg6MTAwJTttYXJnaW4tYm90dG9t
OjIwcHh9LnRhYmxlIHRoLC50YWJsZSB0ZHtwYWRkaW5nOjhweDtsaW5lLWhlaWdodDoyMHB4O3RleHQt
YWxpZ246bGVmdDt2ZXJ0aWNhbC1hbGlnbjp0b3A7Ym9yZGVyLXRvcDoxcHggc29saWQgI2RkZH0udGFi
bGUgdGh7Zm9udC13ZWlnaHQ6Ym9sZH0udGFibGUgdGhlYWQgdGh7dmVydGljYWwtYWxpZ246Ym90dG9t
fS50YWJsZSBjYXB0aW9uK3RoZWFkIHRyOmZpcnN0LWNoaWxkIHRoLC50YWJsZSBjYXB0aW9uK3RoZWFk
IHRyOmZpcnN0LWNoaWxkIHRkLC50YWJsZSBjb2xncm91cCt0aGVhZCB0cjpmaXJzdC1jaGlsZCB0aCwu
dGFibGUgY29sZ3JvdXArdGhlYWQgdHI6Zmlyc3QtY2hpbGQgdGQsLnRhYmxlIHRoZWFkOmZpcnN0LWNo
aWxkIHRyOmZpcnN0LWNoaWxkIHRoLC50YWJsZSB0aGVhZDpmaXJzdC1jaGlsZCB0cjpmaXJzdC1jaGls
ZCB0ZHtib3JkZXItdG9wOjB9LnRhYmxlIHRib2R5K3Rib2R5e2JvcmRlci10b3A6MnB4IHNvbGlkICNk
ZGR9LnRhYmxlIC50YWJsZXtiYWNrZ3JvdW5kLWNvbG9yOiNmZmZ9LnRhYmxlLWNvbmRlbnNlZCB0aCwu
dGFibGUtY29uZGVuc2VkIHRke3BhZGRpbmc6NHB4IDVweH0udGFibGUtYm9yZGVyZWR7Ym9yZGVyOjFw
eCBzb2xpZCAjZGRkO2JvcmRlci1jb2xsYXBzZTpzZXBhcmF0ZTsqYm9yZGVyLWNvbGxhcHNlOmNvbGxh
cHNlO2JvcmRlci1sZWZ0OjA7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjRweDstbW96LWJvcmRlci1yYWRp
dXM6NHB4O2JvcmRlci1yYWRpdXM6NHB4fS50YWJsZS1ib3JkZXJlZCB0aCwudGFibGUtYm9yZGVyZWQg
dGR7Ym9yZGVyLWxlZnQ6MXB4IHNvbGlkICNkZGR9LnRhYmxlLWJvcmRlcmVkIGNhcHRpb24rdGhlYWQg
dHI6Zmlyc3QtY2hpbGQgdGgsLnRhYmxlLWJvcmRlcmVkIGNhcHRpb24rdGJvZHkgdHI6Zmlyc3QtY2hp
bGQgdGgsLnRhYmxlLWJvcmRlcmVkIGNhcHRpb24rdGJvZHkgdHI6Zmlyc3QtY2hpbGQgdGQsLnRhYmxl
LWJvcmRlcmVkIGNvbGdyb3VwK3RoZWFkIHRyOmZpcnN0LWNoaWxkIHRoLC50YWJsZS1ib3JkZXJlZCBj
b2xncm91cCt0Ym9keSB0cjpmaXJzdC1jaGlsZCB0aCwudGFibGUtYm9yZGVyZWQgY29sZ3JvdXArdGJv
ZHkgdHI6Zmlyc3QtY2hpbGQgdGQsLnRhYmxlLWJvcmRlcmVkIHRoZWFkOmZpcnN0LWNoaWxkIHRyOmZp
cnN0LWNoaWxkIHRoLC50YWJsZS1ib3JkZXJlZCB0Ym9keTpmaXJzdC1jaGlsZCB0cjpmaXJzdC1jaGls
ZCB0aCwudGFibGUtYm9yZGVyZWQgdGJvZHk6Zmlyc3QtY2hpbGQgdHI6Zmlyc3QtY2hpbGQgdGR7Ym9y
ZGVyLXRvcDowfS50YWJsZS1ib3JkZXJlZCB0aGVhZDpmaXJzdC1jaGlsZCB0cjpmaXJzdC1jaGlsZD50
aDpmaXJzdC1jaGlsZCwudGFibGUtYm9yZGVyZWQgdGJvZHk6Zmlyc3QtY2hpbGQgdHI6Zmlyc3QtY2hp
bGQ+dGQ6Zmlyc3QtY2hpbGQsLnRhYmxlLWJvcmRlcmVkIHRib2R5OmZpcnN0LWNoaWxkIHRyOmZpcnN0
LWNoaWxkPnRoOmZpcnN0LWNoaWxkey13ZWJraXQtYm9yZGVyLXRvcC1sZWZ0LXJhZGl1czo0cHg7Ym9y
ZGVyLXRvcC1sZWZ0LXJhZGl1czo0cHg7LW1vei1ib3JkZXItcmFkaXVzLXRvcGxlZnQ6NHB4fS50YWJs
ZS1ib3JkZXJlZCB0aGVhZDpmaXJzdC1jaGlsZCB0cjpmaXJzdC1jaGlsZD50aDpsYXN0LWNoaWxkLC50
YWJsZS1ib3JkZXJlZCB0Ym9keTpmaXJzdC1jaGlsZCB0cjpmaXJzdC1jaGlsZD50ZDpsYXN0LWNoaWxk
LC50YWJsZS1ib3JkZXJlZCB0Ym9keTpmaXJzdC1jaGlsZCB0cjpmaXJzdC1jaGlsZD50aDpsYXN0LWNo
aWxkey13ZWJraXQtYm9yZGVyLXRvcC1yaWdodC1yYWRpdXM6NHB4O2JvcmRlci10b3AtcmlnaHQtcmFk
aXVzOjRweDstbW96LWJvcmRlci1yYWRpdXMtdG9wcmlnaHQ6NHB4fS50YWJsZS1ib3JkZXJlZCB0aGVh
ZDpsYXN0LWNoaWxkIHRyOmxhc3QtY2hpbGQ+dGg6Zmlyc3QtY2hpbGQsLnRhYmxlLWJvcmRlcmVkIHRi
b2R5Omxhc3QtY2hpbGQgdHI6bGFzdC1jaGlsZD50ZDpmaXJzdC1jaGlsZCwudGFibGUtYm9yZGVyZWQg
dGJvZHk6bGFzdC1jaGlsZCB0cjpsYXN0LWNoaWxkPnRoOmZpcnN0LWNoaWxkLC50YWJsZS1ib3JkZXJl
ZCB0Zm9vdDpsYXN0LWNoaWxkIHRyOmxhc3QtY2hpbGQ+dGQ6Zmlyc3QtY2hpbGQsLnRhYmxlLWJvcmRl
cmVkIHRmb290Omxhc3QtY2hpbGQgdHI6bGFzdC1jaGlsZD50aDpmaXJzdC1jaGlsZHstd2Via2l0LWJv
cmRlci1ib3R0b20tbGVmdC1yYWRpdXM6NHB4O2JvcmRlci1ib3R0b20tbGVmdC1yYWRpdXM6NHB4Oy1t
b3otYm9yZGVyLXJhZGl1cy1ib3R0b21sZWZ0OjRweH0udGFibGUtYm9yZGVyZWQgdGhlYWQ6bGFzdC1j
aGlsZCB0cjpsYXN0LWNoaWxkPnRoOmxhc3QtY2hpbGQsLnRhYmxlLWJvcmRlcmVkIHRib2R5Omxhc3Qt
Y2hpbGQgdHI6bGFzdC1jaGlsZD50ZDpsYXN0LWNoaWxkLC50YWJsZS1ib3JkZXJlZCB0Ym9keTpsYXN0
LWNoaWxkIHRyOmxhc3QtY2hpbGQ+dGg6bGFzdC1jaGlsZCwudGFibGUtYm9yZGVyZWQgdGZvb3Q6bGFz
dC1jaGlsZCB0cjpsYXN0LWNoaWxkPnRkOmxhc3QtY2hpbGQsLnRhYmxlLWJvcmRlcmVkIHRmb290Omxh
c3QtY2hpbGQgdHI6bGFzdC1jaGlsZD50aDpsYXN0LWNoaWxkey13ZWJraXQtYm9yZGVyLWJvdHRvbS1y
aWdodC1yYWRpdXM6NHB4O2JvcmRlci1ib3R0b20tcmlnaHQtcmFkaXVzOjRweDstbW96LWJvcmRlci1y
YWRpdXMtYm90dG9tcmlnaHQ6NHB4fS50YWJsZS1ib3JkZXJlZCB0Zm9vdCt0Ym9keTpsYXN0LWNoaWxk
IHRyOmxhc3QtY2hpbGQgdGQ6Zmlyc3QtY2hpbGR7LXdlYmtpdC1ib3JkZXItYm90dG9tLWxlZnQtcmFk
aXVzOjA7Ym9yZGVyLWJvdHRvbS1sZWZ0LXJhZGl1czowOy1tb3otYm9yZGVyLXJhZGl1cy1ib3R0b21s
ZWZ0OjB9LnRhYmxlLWJvcmRlcmVkIHRmb290K3Rib2R5Omxhc3QtY2hpbGQgdHI6bGFzdC1jaGlsZCB0
ZDpsYXN0LWNoaWxkey13ZWJraXQtYm9yZGVyLWJvdHRvbS1yaWdodC1yYWRpdXM6MDtib3JkZXItYm90
dG9tLXJpZ2h0LXJhZGl1czowOy1tb3otYm9yZGVyLXJhZGl1cy1ib3R0b21yaWdodDowfS50YWJsZS1i
b3JkZXJlZCBjYXB0aW9uK3RoZWFkIHRyOmZpcnN0LWNoaWxkIHRoOmZpcnN0LWNoaWxkLC50YWJsZS1i
b3JkZXJlZCBjYXB0aW9uK3Rib2R5IHRyOmZpcnN0LWNoaWxkIHRkOmZpcnN0LWNoaWxkLC50YWJsZS1i
b3JkZXJlZCBjb2xncm91cCt0aGVhZCB0cjpmaXJzdC1jaGlsZCB0aDpmaXJzdC1jaGlsZCwudGFibGUt
Ym9yZGVyZWQgY29sZ3JvdXArdGJvZHkgdHI6Zmlyc3QtY2hpbGQgdGQ6Zmlyc3QtY2hpbGR7LXdlYmtp
dC1ib3JkZXItdG9wLWxlZnQtcmFkaXVzOjRweDtib3JkZXItdG9wLWxlZnQtcmFkaXVzOjRweDstbW96
LWJvcmRlci1yYWRpdXMtdG9wbGVmdDo0cHh9LnRhYmxlLWJvcmRlcmVkIGNhcHRpb24rdGhlYWQgdHI6
Zmlyc3QtY2hpbGQgdGg6bGFzdC1jaGlsZCwudGFibGUtYm9yZGVyZWQgY2FwdGlvbit0Ym9keSB0cjpm
aXJzdC1jaGlsZCB0ZDpsYXN0LWNoaWxkLC50YWJsZS1ib3JkZXJlZCBjb2xncm91cCt0aGVhZCB0cjpm
aXJzdC1jaGlsZCB0aDpsYXN0LWNoaWxkLC50YWJsZS1ib3JkZXJlZCBjb2xncm91cCt0Ym9keSB0cjpm
aXJzdC1jaGlsZCB0ZDpsYXN0LWNoaWxkey13ZWJraXQtYm9yZGVyLXRvcC1yaWdodC1yYWRpdXM6NHB4
O2JvcmRlci10b3AtcmlnaHQtcmFkaXVzOjRweDstbW96LWJvcmRlci1yYWRpdXMtdG9wcmlnaHQ6NHB4
fS50YWJsZS1zdHJpcGVkIHRib2R5PnRyOm50aC1jaGlsZChvZGQpPnRkLC50YWJsZS1zdHJpcGVkIHRi
b2R5PnRyOm50aC1jaGlsZChvZGQpPnRoe2JhY2tncm91bmQtY29sb3I6I2Y5ZjlmOX0udGFibGUtaG92
ZXIgdGJvZHkgdHI6aG92ZXI+dGQsLnRhYmxlLWhvdmVyIHRib2R5IHRyOmhvdmVyPnRoe2JhY2tncm91
bmQtY29sb3I6I2Y1ZjVmNX10YWJsZSB0ZFtjbGFzcyo9InNwYW4iXSx0YWJsZSB0aFtjbGFzcyo9InNw
YW4iXSwucm93LWZsdWlkIHRhYmxlIHRkW2NsYXNzKj0ic3BhbiJdLC5yb3ctZmx1aWQgdGFibGUgdGhb
Y2xhc3MqPSJzcGFuIl17ZGlzcGxheTp0YWJsZS1jZWxsO2Zsb2F0Om5vbmU7bWFyZ2luLWxlZnQ6MH0u
dGFibGUgdGQuc3BhbjEsLnRhYmxlIHRoLnNwYW4xe2Zsb2F0Om5vbmU7d2lkdGg6NDRweDttYXJnaW4t
bGVmdDowfS50YWJsZSB0ZC5zcGFuMiwudGFibGUgdGguc3BhbjJ7ZmxvYXQ6bm9uZTt3aWR0aDoxMjRw
eDttYXJnaW4tbGVmdDowfS50YWJsZSB0ZC5zcGFuMywudGFibGUgdGguc3BhbjN7ZmxvYXQ6bm9uZTt3
aWR0aDoyMDRweDttYXJnaW4tbGVmdDowfS50YWJsZSB0ZC5zcGFuNCwudGFibGUgdGguc3BhbjR7Zmxv
YXQ6bm9uZTt3aWR0aDoyODRweDttYXJnaW4tbGVmdDowfS50YWJsZSB0ZC5zcGFuNSwudGFibGUgdGgu
c3BhbjV7ZmxvYXQ6bm9uZTt3aWR0aDozNjRweDttYXJnaW4tbGVmdDowfS50YWJsZSB0ZC5zcGFuNiwu
dGFibGUgdGguc3BhbjZ7ZmxvYXQ6bm9uZTt3aWR0aDo0NDRweDttYXJnaW4tbGVmdDowfS50YWJsZSB0
ZC5zcGFuNywudGFibGUgdGguc3Bhbjd7ZmxvYXQ6bm9uZTt3aWR0aDo1MjRweDttYXJnaW4tbGVmdDow
fS50YWJsZSB0ZC5zcGFuOCwudGFibGUgdGguc3Bhbjh7ZmxvYXQ6bm9uZTt3aWR0aDo2MDRweDttYXJn
aW4tbGVmdDowfS50YWJsZSB0ZC5zcGFuOSwudGFibGUgdGguc3Bhbjl7ZmxvYXQ6bm9uZTt3aWR0aDo2
ODRweDttYXJnaW4tbGVmdDowfS50YWJsZSB0ZC5zcGFuMTAsLnRhYmxlIHRoLnNwYW4xMHtmbG9hdDpu
b25lO3dpZHRoOjc2NHB4O21hcmdpbi1sZWZ0OjB9LnRhYmxlIHRkLnNwYW4xMSwudGFibGUgdGguc3Bh
bjExe2Zsb2F0Om5vbmU7d2lkdGg6ODQ0cHg7bWFyZ2luLWxlZnQ6MH0udGFibGUgdGQuc3BhbjEyLC50
YWJsZSB0aC5zcGFuMTJ7ZmxvYXQ6bm9uZTt3aWR0aDo5MjRweDttYXJnaW4tbGVmdDowfS50YWJsZSB0
Ym9keSB0ci5zdWNjZXNzPnRke2JhY2tncm91bmQtY29sb3I6I2RmZjBkOH0udGFibGUgdGJvZHkgdHIu
ZXJyb3I+dGR7YmFja2dyb3VuZC1jb2xvcjojZjJkZWRlfS50YWJsZSB0Ym9keSB0ci53YXJuaW5nPnRk
e2JhY2tncm91bmQtY29sb3I6I2ZjZjhlM30udGFibGUgdGJvZHkgdHIuaW5mbz50ZHtiYWNrZ3JvdW5k
LWNvbG9yOiNkOWVkZjd9LnRhYmxlLWhvdmVyIHRib2R5IHRyLnN1Y2Nlc3M6aG92ZXI+dGR7YmFja2dy
b3VuZC1jb2xvcjojZDBlOWM2fS50YWJsZS1ob3ZlciB0Ym9keSB0ci5lcnJvcjpob3Zlcj50ZHtiYWNr
Z3JvdW5kLWNvbG9yOiNlYmNjY2N9LnRhYmxlLWhvdmVyIHRib2R5IHRyLndhcm5pbmc6aG92ZXI+dGR7
YmFja2dyb3VuZC1jb2xvcjojZmFmMmNjfS50YWJsZS1ob3ZlciB0Ym9keSB0ci5pbmZvOmhvdmVyPnRk
e2JhY2tncm91bmQtY29sb3I6I2M0ZTNmM31bY2xhc3NePSJpY29uLSJdLFtjbGFzcyo9IiBpY29uLSJd
e2Rpc3BsYXk6aW5saW5lLWJsb2NrO3dpZHRoOjE0cHg7aGVpZ2h0OjE0cHg7bWFyZ2luLXRvcDoxcHg7
Km1hcmdpbi1yaWdodDouM2VtO2xpbmUtaGVpZ2h0OjE0cHg7dmVydGljYWwtYWxpZ246dGV4dC10b3A7
YmFja2dyb3VuZC1pbWFnZTp1cmwoIi4uL2ltZy9nbHlwaGljb25zLWhhbGZsaW5ncy5wbmciKTtiYWNr
Z3JvdW5kLXBvc2l0aW9uOjE0cHggMTRweDtiYWNrZ3JvdW5kLXJlcGVhdDpuby1yZXBlYXR9Lmljb24t
d2hpdGUsLm5hdi1waWxscz4uYWN0aXZlPmE+W2NsYXNzXj0iaWNvbi0iXSwubmF2LXBpbGxzPi5hY3Rp
dmU+YT5bY2xhc3MqPSIgaWNvbi0iXSwubmF2LWxpc3Q+LmFjdGl2ZT5hPltjbGFzc149Imljb24tIl0s
Lm5hdi1saXN0Pi5hY3RpdmU+YT5bY2xhc3MqPSIgaWNvbi0iXSwubmF2YmFyLWludmVyc2UgLm5hdj4u
YWN0aXZlPmE+W2NsYXNzXj0iaWNvbi0iXSwubmF2YmFyLWludmVyc2UgLm5hdj4uYWN0aXZlPmE+W2Ns
YXNzKj0iIGljb24tIl0sLmRyb3Bkb3duLW1lbnU+bGk+YTpob3Zlcj5bY2xhc3NePSJpY29uLSJdLC5k
cm9wZG93bi1tZW51PmxpPmE6Zm9jdXM+W2NsYXNzXj0iaWNvbi0iXSwuZHJvcGRvd24tbWVudT5saT5h
OmhvdmVyPltjbGFzcyo9IiBpY29uLSJdLC5kcm9wZG93bi1tZW51PmxpPmE6Zm9jdXM+W2NsYXNzKj0i
IGljb24tIl0sLmRyb3Bkb3duLW1lbnU+LmFjdGl2ZT5hPltjbGFzc149Imljb24tIl0sLmRyb3Bkb3du
LW1lbnU+LmFjdGl2ZT5hPltjbGFzcyo9IiBpY29uLSJdLC5kcm9wZG93bi1zdWJtZW51OmhvdmVyPmE+
W2NsYXNzXj0iaWNvbi0iXSwuZHJvcGRvd24tc3VibWVudTpmb2N1cz5hPltjbGFzc149Imljb24tIl0s
LmRyb3Bkb3duLXN1Ym1lbnU6aG92ZXI+YT5bY2xhc3MqPSIgaWNvbi0iXSwuZHJvcGRvd24tc3VibWVu
dTpmb2N1cz5hPltjbGFzcyo9IiBpY29uLSJde2JhY2tncm91bmQtaW1hZ2U6dXJsKCIuLi9pbWcvZ2x5
cGhpY29ucy1oYWxmbGluZ3Mtd2hpdGUucG5nIil9Lmljb24tZ2xhc3N7YmFja2dyb3VuZC1wb3NpdGlv
bjowIDB9Lmljb24tbXVzaWN7YmFja2dyb3VuZC1wb3NpdGlvbjotMjRweCAwfS5pY29uLXNlYXJjaHti
YWNrZ3JvdW5kLXBvc2l0aW9uOi00OHB4IDB9Lmljb24tZW52ZWxvcGV7YmFja2dyb3VuZC1wb3NpdGlv
bjotNzJweCAwfS5pY29uLWhlYXJ0e2JhY2tncm91bmQtcG9zaXRpb246LTk2cHggMH0uaWNvbi1zdGFy
e2JhY2tncm91bmQtcG9zaXRpb246LTEyMHB4IDB9Lmljb24tc3Rhci1lbXB0eXtiYWNrZ3JvdW5kLXBv
c2l0aW9uOi0xNDRweCAwfS5pY29uLXVzZXJ7YmFja2dyb3VuZC1wb3NpdGlvbjotMTY4cHggMH0uaWNv
bi1maWxte2JhY2tncm91bmQtcG9zaXRpb246LTE5MnB4IDB9Lmljb24tdGgtbGFyZ2V7YmFja2dyb3Vu
ZC1wb3NpdGlvbjotMjE2cHggMH0uaWNvbi10aHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yNDBweCAwfS5p
Y29uLXRoLWxpc3R7YmFja2dyb3VuZC1wb3NpdGlvbjotMjY0cHggMH0uaWNvbi1va3tiYWNrZ3JvdW5k
LXBvc2l0aW9uOi0yODhweCAwfS5pY29uLXJlbW92ZXtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zMTJweCAw
fS5pY29uLXpvb20taW57YmFja2dyb3VuZC1wb3NpdGlvbjotMzM2cHggMH0uaWNvbi16b29tLW91dHti
YWNrZ3JvdW5kLXBvc2l0aW9uOi0zNjBweCAwfS5pY29uLW9mZntiYWNrZ3JvdW5kLXBvc2l0aW9uOi0z
ODRweCAwfS5pY29uLXNpZ25hbHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi00MDhweCAwfS5pY29uLWNvZ3ti
YWNrZ3JvdW5kLXBvc2l0aW9uOi00MzJweCAwfS5pY29uLXRyYXNoe2JhY2tncm91bmQtcG9zaXRpb246
LTQ1NnB4IDB9Lmljb24taG9tZXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjAgLTI0cHh9Lmljb24tZmlsZXti
YWNrZ3JvdW5kLXBvc2l0aW9uOi0yNHB4IC0yNHB4fS5pY29uLXRpbWV7YmFja2dyb3VuZC1wb3NpdGlv
bjotNDhweCAtMjRweH0uaWNvbi1yb2Fke2JhY2tncm91bmQtcG9zaXRpb246LTcycHggLTI0cHh9Lmlj
b24tZG93bmxvYWQtYWx0e2JhY2tncm91bmQtcG9zaXRpb246LTk2cHggLTI0cHh9Lmljb24tZG93bmxv
YWR7YmFja2dyb3VuZC1wb3NpdGlvbjotMTIwcHggLTI0cHh9Lmljb24tdXBsb2Fke2JhY2tncm91bmQt
cG9zaXRpb246LTE0NHB4IC0yNHB4fS5pY29uLWluYm94e2JhY2tncm91bmQtcG9zaXRpb246LTE2OHB4
IC0yNHB4fS5pY29uLXBsYXktY2lyY2xle2JhY2tncm91bmQtcG9zaXRpb246LTE5MnB4IC0yNHB4fS5p
Y29uLXJlcGVhdHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yMTZweCAtMjRweH0uaWNvbi1yZWZyZXNoe2Jh
Y2tncm91bmQtcG9zaXRpb246LTI0MHB4IC0yNHB4fS5pY29uLWxpc3QtYWx0e2JhY2tncm91bmQtcG9z
aXRpb246LTI2NHB4IC0yNHB4fS5pY29uLWxvY2t7YmFja2dyb3VuZC1wb3NpdGlvbjotMjg3cHggLTI0
cHh9Lmljb24tZmxhZ3tiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zMTJweCAtMjRweH0uaWNvbi1oZWFkcGhv
bmVze2JhY2tncm91bmQtcG9zaXRpb246LTMzNnB4IC0yNHB4fS5pY29uLXZvbHVtZS1vZmZ7YmFja2dy
b3VuZC1wb3NpdGlvbjotMzYwcHggLTI0cHh9Lmljb24tdm9sdW1lLWRvd257YmFja2dyb3VuZC1wb3Np
dGlvbjotMzg0cHggLTI0cHh9Lmljb24tdm9sdW1lLXVwe2JhY2tncm91bmQtcG9zaXRpb246LTQwOHB4
IC0yNHB4fS5pY29uLXFyY29kZXtiYWNrZ3JvdW5kLXBvc2l0aW9uOi00MzJweCAtMjRweH0uaWNvbi1i
YXJjb2Rle2JhY2tncm91bmQtcG9zaXRpb246LTQ1NnB4IC0yNHB4fS5pY29uLXRhZ3tiYWNrZ3JvdW5k
LXBvc2l0aW9uOjAgLTQ4cHh9Lmljb24tdGFnc3tiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yNXB4IC00OHB4
fS5pY29uLWJvb2t7YmFja2dyb3VuZC1wb3NpdGlvbjotNDhweCAtNDhweH0uaWNvbi1ib29rbWFya3ti
YWNrZ3JvdW5kLXBvc2l0aW9uOi03MnB4IC00OHB4fS5pY29uLXByaW50e2JhY2tncm91bmQtcG9zaXRp
b246LTk2cHggLTQ4cHh9Lmljb24tY2FtZXJhe2JhY2tncm91bmQtcG9zaXRpb246LTEyMHB4IC00OHB4
fS5pY29uLWZvbnR7YmFja2dyb3VuZC1wb3NpdGlvbjotMTQ0cHggLTQ4cHh9Lmljb24tYm9sZHtiYWNr
Z3JvdW5kLXBvc2l0aW9uOi0xNjdweCAtNDhweH0uaWNvbi1pdGFsaWN7YmFja2dyb3VuZC1wb3NpdGlv
bjotMTkycHggLTQ4cHh9Lmljb24tdGV4dC1oZWlnaHR7YmFja2dyb3VuZC1wb3NpdGlvbjotMjE2cHgg
LTQ4cHh9Lmljb24tdGV4dC13aWR0aHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yNDBweCAtNDhweH0uaWNv
bi1hbGlnbi1sZWZ0e2JhY2tncm91bmQtcG9zaXRpb246LTI2NHB4IC00OHB4fS5pY29uLWFsaWduLWNl
bnRlcntiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yODhweCAtNDhweH0uaWNvbi1hbGlnbi1yaWdodHtiYWNr
Z3JvdW5kLXBvc2l0aW9uOi0zMTJweCAtNDhweH0uaWNvbi1hbGlnbi1qdXN0aWZ5e2JhY2tncm91bmQt
cG9zaXRpb246LTMzNnB4IC00OHB4fS5pY29uLWxpc3R7YmFja2dyb3VuZC1wb3NpdGlvbjotMzYwcHgg
LTQ4cHh9Lmljb24taW5kZW50LWxlZnR7YmFja2dyb3VuZC1wb3NpdGlvbjotMzg0cHggLTQ4cHh9Lmlj
b24taW5kZW50LXJpZ2h0e2JhY2tncm91bmQtcG9zaXRpb246LTQwOHB4IC00OHB4fS5pY29uLWZhY2V0
aW1lLXZpZGVve2JhY2tncm91bmQtcG9zaXRpb246LTQzMnB4IC00OHB4fS5pY29uLXBpY3R1cmV7YmFj
a2dyb3VuZC1wb3NpdGlvbjotNDU2cHggLTQ4cHh9Lmljb24tcGVuY2lse2JhY2tncm91bmQtcG9zaXRp
b246MCAtNzJweH0uaWNvbi1tYXAtbWFya2Vye2JhY2tncm91bmQtcG9zaXRpb246LTI0cHggLTcycHh9
Lmljb24tYWRqdXN0e2JhY2tncm91bmQtcG9zaXRpb246LTQ4cHggLTcycHh9Lmljb24tdGludHtiYWNr
Z3JvdW5kLXBvc2l0aW9uOi03MnB4IC03MnB4fS5pY29uLWVkaXR7YmFja2dyb3VuZC1wb3NpdGlvbjot
OTZweCAtNzJweH0uaWNvbi1zaGFyZXtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0xMjBweCAtNzJweH0uaWNv
bi1jaGVja3tiYWNrZ3JvdW5kLXBvc2l0aW9uOi0xNDRweCAtNzJweH0uaWNvbi1tb3Zle2JhY2tncm91
bmQtcG9zaXRpb246LTE2OHB4IC03MnB4fS5pY29uLXN0ZXAtYmFja3dhcmR7YmFja2dyb3VuZC1wb3Np
dGlvbjotMTkycHggLTcycHh9Lmljb24tZmFzdC1iYWNrd2FyZHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0y
MTZweCAtNzJweH0uaWNvbi1iYWNrd2FyZHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yNDBweCAtNzJweH0u
aWNvbi1wbGF5e2JhY2tncm91bmQtcG9zaXRpb246LTI2NHB4IC03MnB4fS5pY29uLXBhdXNle2JhY2tn
cm91bmQtcG9zaXRpb246LTI4OHB4IC03MnB4fS5pY29uLXN0b3B7YmFja2dyb3VuZC1wb3NpdGlvbjot
MzEycHggLTcycHh9Lmljb24tZm9yd2FyZHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zMzZweCAtNzJweH0u
aWNvbi1mYXN0LWZvcndhcmR7YmFja2dyb3VuZC1wb3NpdGlvbjotMzYwcHggLTcycHh9Lmljb24tc3Rl
cC1mb3J3YXJke2JhY2tncm91bmQtcG9zaXRpb246LTM4NHB4IC03MnB4fS5pY29uLWVqZWN0e2JhY2tn
cm91bmQtcG9zaXRpb246LTQwOHB4IC03MnB4fS5pY29uLWNoZXZyb24tbGVmdHtiYWNrZ3JvdW5kLXBv
c2l0aW9uOi00MzJweCAtNzJweH0uaWNvbi1jaGV2cm9uLXJpZ2h0e2JhY2tncm91bmQtcG9zaXRpb246
LTQ1NnB4IC03MnB4fS5pY29uLXBsdXMtc2lnbntiYWNrZ3JvdW5kLXBvc2l0aW9uOjAgLTk2cHh9Lmlj
b24tbWludXMtc2lnbntiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yNHB4IC05NnB4fS5pY29uLXJlbW92ZS1z
aWdue2JhY2tncm91bmQtcG9zaXRpb246LTQ4cHggLTk2cHh9Lmljb24tb2stc2lnbntiYWNrZ3JvdW5k
LXBvc2l0aW9uOi03MnB4IC05NnB4fS5pY29uLXF1ZXN0aW9uLXNpZ257YmFja2dyb3VuZC1wb3NpdGlv
bjotOTZweCAtOTZweH0uaWNvbi1pbmZvLXNpZ257YmFja2dyb3VuZC1wb3NpdGlvbjotMTIwcHggLTk2
cHh9Lmljb24tc2NyZWVuc2hvdHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0xNDRweCAtOTZweH0uaWNvbi1y
ZW1vdmUtY2lyY2xle2JhY2tncm91bmQtcG9zaXRpb246LTE2OHB4IC05NnB4fS5pY29uLW9rLWNpcmNs
ZXtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0xOTJweCAtOTZweH0uaWNvbi1iYW4tY2lyY2xle2JhY2tncm91
bmQtcG9zaXRpb246LTIxNnB4IC05NnB4fS5pY29uLWFycm93LWxlZnR7YmFja2dyb3VuZC1wb3NpdGlv
bjotMjQwcHggLTk2cHh9Lmljb24tYXJyb3ctcmlnaHR7YmFja2dyb3VuZC1wb3NpdGlvbjotMjY0cHgg
LTk2cHh9Lmljb24tYXJyb3ctdXB7YmFja2dyb3VuZC1wb3NpdGlvbjotMjg5cHggLTk2cHh9Lmljb24t
YXJyb3ctZG93bntiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zMTJweCAtOTZweH0uaWNvbi1zaGFyZS1hbHR7
YmFja2dyb3VuZC1wb3NpdGlvbjotMzM2cHggLTk2cHh9Lmljb24tcmVzaXplLWZ1bGx7YmFja2dyb3Vu
ZC1wb3NpdGlvbjotMzYwcHggLTk2cHh9Lmljb24tcmVzaXplLXNtYWxse2JhY2tncm91bmQtcG9zaXRp
b246LTM4NHB4IC05NnB4fS5pY29uLXBsdXN7YmFja2dyb3VuZC1wb3NpdGlvbjotNDA4cHggLTk2cHh9
Lmljb24tbWludXN7YmFja2dyb3VuZC1wb3NpdGlvbjotNDMzcHggLTk2cHh9Lmljb24tYXN0ZXJpc2t7
YmFja2dyb3VuZC1wb3NpdGlvbjotNDU2cHggLTk2cHh9Lmljb24tZXhjbGFtYXRpb24tc2lnbntiYWNr
Z3JvdW5kLXBvc2l0aW9uOjAgLTEyMHB4fS5pY29uLWdpZnR7YmFja2dyb3VuZC1wb3NpdGlvbjotMjRw
eCAtMTIwcHh9Lmljb24tbGVhZntiYWNrZ3JvdW5kLXBvc2l0aW9uOi00OHB4IC0xMjBweH0uaWNvbi1m
aXJle2JhY2tncm91bmQtcG9zaXRpb246LTcycHggLTEyMHB4fS5pY29uLWV5ZS1vcGVue2JhY2tncm91
bmQtcG9zaXRpb246LTk2cHggLTEyMHB4fS5pY29uLWV5ZS1jbG9zZXtiYWNrZ3JvdW5kLXBvc2l0aW9u
Oi0xMjBweCAtMTIwcHh9Lmljb24td2FybmluZy1zaWdue2JhY2tncm91bmQtcG9zaXRpb246LTE0NHB4
IC0xMjBweH0uaWNvbi1wbGFuZXtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0xNjhweCAtMTIwcHh9Lmljb24t
Y2FsZW5kYXJ7YmFja2dyb3VuZC1wb3NpdGlvbjotMTkycHggLTEyMHB4fS5pY29uLXJhbmRvbXt3aWR0
aDoxNnB4O2JhY2tncm91bmQtcG9zaXRpb246LTIxNnB4IC0xMjBweH0uaWNvbi1jb21tZW50e2JhY2tn
cm91bmQtcG9zaXRpb246LTI0MHB4IC0xMjBweH0uaWNvbi1tYWduZXR7YmFja2dyb3VuZC1wb3NpdGlv
bjotMjY0cHggLTEyMHB4fS5pY29uLWNoZXZyb24tdXB7YmFja2dyb3VuZC1wb3NpdGlvbjotMjg4cHgg
LTEyMHB4fS5pY29uLWNoZXZyb24tZG93bntiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zMTNweCAtMTE5cHh9
Lmljb24tcmV0d2VldHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zMzZweCAtMTIwcHh9Lmljb24tc2hvcHBp
bmctY2FydHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zNjBweCAtMTIwcHh9Lmljb24tZm9sZGVyLWNsb3Nl
e3dpZHRoOjE2cHg7YmFja2dyb3VuZC1wb3NpdGlvbjotMzg0cHggLTEyMHB4fS5pY29uLWZvbGRlci1v
cGVue3dpZHRoOjE2cHg7YmFja2dyb3VuZC1wb3NpdGlvbjotNDA4cHggLTEyMHB4fS5pY29uLXJlc2l6
ZS12ZXJ0aWNhbHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi00MzJweCAtMTE5cHh9Lmljb24tcmVzaXplLWhv
cml6b250YWx7YmFja2dyb3VuZC1wb3NpdGlvbjotNDU2cHggLTExOHB4fS5pY29uLWhkZHtiYWNrZ3Jv
dW5kLXBvc2l0aW9uOjAgLTE0NHB4fS5pY29uLWJ1bGxob3Jue2JhY2tncm91bmQtcG9zaXRpb246LTI0
cHggLTE0NHB4fS5pY29uLWJlbGx7YmFja2dyb3VuZC1wb3NpdGlvbjotNDhweCAtMTQ0cHh9Lmljb24t
Y2VydGlmaWNhdGV7YmFja2dyb3VuZC1wb3NpdGlvbjotNzJweCAtMTQ0cHh9Lmljb24tdGh1bWJzLXVw
e2JhY2tncm91bmQtcG9zaXRpb246LTk2cHggLTE0NHB4fS5pY29uLXRodW1icy1kb3due2JhY2tncm91
bmQtcG9zaXRpb246LTEyMHB4IC0xNDRweH0uaWNvbi1oYW5kLXJpZ2h0e2JhY2tncm91bmQtcG9zaXRp
b246LTE0NHB4IC0xNDRweH0uaWNvbi1oYW5kLWxlZnR7YmFja2dyb3VuZC1wb3NpdGlvbjotMTY4cHgg
LTE0NHB4fS5pY29uLWhhbmQtdXB7YmFja2dyb3VuZC1wb3NpdGlvbjotMTkycHggLTE0NHB4fS5pY29u
LWhhbmQtZG93bntiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yMTZweCAtMTQ0cHh9Lmljb24tY2lyY2xlLWFy
cm93LXJpZ2h0e2JhY2tncm91bmQtcG9zaXRpb246LTI0MHB4IC0xNDRweH0uaWNvbi1jaXJjbGUtYXJy
b3ctbGVmdHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yNjRweCAtMTQ0cHh9Lmljb24tY2lyY2xlLWFycm93
LXVwe2JhY2tncm91bmQtcG9zaXRpb246LTI4OHB4IC0xNDRweH0uaWNvbi1jaXJjbGUtYXJyb3ctZG93
bntiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zMTJweCAtMTQ0cHh9Lmljb24tZ2xvYmV7YmFja2dyb3VuZC1w
b3NpdGlvbjotMzM2cHggLTE0NHB4fS5pY29uLXdyZW5jaHtiYWNrZ3JvdW5kLXBvc2l0aW9uOi0zNjBw
eCAtMTQ0cHh9Lmljb24tdGFza3N7YmFja2dyb3VuZC1wb3NpdGlvbjotMzg0cHggLTE0NHB4fS5pY29u
LWZpbHRlcntiYWNrZ3JvdW5kLXBvc2l0aW9uOi00MDhweCAtMTQ0cHh9Lmljb24tYnJpZWZjYXNle2Jh
Y2tncm91bmQtcG9zaXRpb246LTQzMnB4IC0xNDRweH0uaWNvbi1mdWxsc2NyZWVue2JhY2tncm91bmQt
cG9zaXRpb246LTQ1NnB4IC0xNDRweH0uZHJvcHVwLC5kcm9wZG93bntwb3NpdGlvbjpyZWxhdGl2ZX0u
ZHJvcGRvd24tdG9nZ2xleyptYXJnaW4tYm90dG9tOi0zcHh9LmRyb3Bkb3duLXRvZ2dsZTphY3RpdmUs
Lm9wZW4gLmRyb3Bkb3duLXRvZ2dsZXtvdXRsaW5lOjB9LmNhcmV0e2Rpc3BsYXk6aW5saW5lLWJsb2Nr
O3dpZHRoOjA7aGVpZ2h0OjA7dmVydGljYWwtYWxpZ246dG9wO2JvcmRlci10b3A6NHB4IHNvbGlkICMw
MDA7Ym9yZGVyLXJpZ2h0OjRweCBzb2xpZCB0cmFuc3BhcmVudDtib3JkZXItbGVmdDo0cHggc29saWQg
dHJhbnNwYXJlbnQ7Y29udGVudDoiIn0uZHJvcGRvd24gLmNhcmV0e21hcmdpbi10b3A6OHB4O21hcmdp
bi1sZWZ0OjJweH0uZHJvcGRvd24tbWVudXtwb3NpdGlvbjphYnNvbHV0ZTt0b3A6MTAwJTtsZWZ0OjA7
ei1pbmRleDoxMDAwO2Rpc3BsYXk6bm9uZTtmbG9hdDpsZWZ0O21pbi13aWR0aDoxNjBweDtwYWRkaW5n
OjVweCAwO21hcmdpbjoycHggMCAwO2xpc3Qtc3R5bGU6bm9uZTtiYWNrZ3JvdW5kLWNvbG9yOiNmZmY7
Ym9yZGVyOjFweCBzb2xpZCAjY2NjO2JvcmRlcjoxcHggc29saWQgcmdiYSgwLDAsMCwwLjIpOypib3Jk
ZXItcmlnaHQtd2lkdGg6MnB4Oypib3JkZXItYm90dG9tLXdpZHRoOjJweDstd2Via2l0LWJvcmRlci1y
YWRpdXM6NnB4Oy1tb3otYm9yZGVyLXJhZGl1czo2cHg7Ym9yZGVyLXJhZGl1czo2cHg7LXdlYmtpdC1i
b3gtc2hhZG93OjAgNXB4IDEwcHggcmdiYSgwLDAsMCwwLjIpOy1tb3otYm94LXNoYWRvdzowIDVweCAx
MHB4IHJnYmEoMCwwLDAsMC4yKTtib3gtc2hhZG93OjAgNXB4IDEwcHggcmdiYSgwLDAsMCwwLjIpOy13
ZWJraXQtYmFja2dyb3VuZC1jbGlwOnBhZGRpbmctYm94Oy1tb3otYmFja2dyb3VuZC1jbGlwOnBhZGRp
bmc7YmFja2dyb3VuZC1jbGlwOnBhZGRpbmctYm94fS5kcm9wZG93bi1tZW51LnB1bGwtcmlnaHR7cmln
aHQ6MDtsZWZ0OmF1dG99LmRyb3Bkb3duLW1lbnUgLmRpdmlkZXJ7KndpZHRoOjEwMCU7aGVpZ2h0OjFw
eDttYXJnaW46OXB4IDFweDsqbWFyZ2luOi01cHggMCA1cHg7b3ZlcmZsb3c6aGlkZGVuO2JhY2tncm91
bmQtY29sb3I6I2U1ZTVlNTtib3JkZXItYm90dG9tOjFweCBzb2xpZCAjZmZmfS5kcm9wZG93bi1tZW51
PmxpPmF7ZGlzcGxheTpibG9jaztwYWRkaW5nOjNweCAyMHB4O2NsZWFyOmJvdGg7Zm9udC13ZWlnaHQ6
bm9ybWFsO2xpbmUtaGVpZ2h0OjIwcHg7Y29sb3I6IzMzMzt3aGl0ZS1zcGFjZTpub3dyYXB9LmRyb3Bk
b3duLW1lbnU+bGk+YTpob3ZlciwuZHJvcGRvd24tbWVudT5saT5hOmZvY3VzLC5kcm9wZG93bi1zdWJt
ZW51OmhvdmVyPmEsLmRyb3Bkb3duLXN1Ym1lbnU6Zm9jdXM+YXtjb2xvcjojZmZmO3RleHQtZGVjb3Jh
dGlvbjpub25lO2JhY2tncm91bmQtY29sb3I6IzAwODFjMjtiYWNrZ3JvdW5kLWltYWdlOi1tb3otbGlu
ZWFyLWdyYWRpZW50KHRvcCwjMDhjLCMwMDc3YjMpO2JhY2tncm91bmQtaW1hZ2U6LXdlYmtpdC1ncmFk
aWVudChsaW5lYXIsMCAwLDAgMTAwJSxmcm9tKCMwOGMpLHRvKCMwMDc3YjMpKTtiYWNrZ3JvdW5kLWlt
YWdlOi13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwjMDhjLCMwMDc3YjMpO2JhY2tncm91bmQtaW1h
Z2U6LW8tbGluZWFyLWdyYWRpZW50KHRvcCwjMDhjLCMwMDc3YjMpO2JhY2tncm91bmQtaW1hZ2U6bGlu
ZWFyLWdyYWRpZW50KHRvIGJvdHRvbSwjMDhjLCMwMDc3YjMpO2JhY2tncm91bmQtcmVwZWF0OnJlcGVh
dC14O2ZpbHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3JhZGllbnQoc3RhcnRD
b2xvcnN0cj0nI2ZmMDA4OGNjJyxlbmRDb2xvcnN0cj0nI2ZmMDA3N2IzJyxHcmFkaWVudFR5cGU9MCl9
LmRyb3Bkb3duLW1lbnU+LmFjdGl2ZT5hLC5kcm9wZG93bi1tZW51Pi5hY3RpdmU+YTpob3ZlciwuZHJv
cGRvd24tbWVudT4uYWN0aXZlPmE6Zm9jdXN7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTti
YWNrZ3JvdW5kLWNvbG9yOiMwMDgxYzI7YmFja2dyb3VuZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVu
dCh0b3AsIzA4YywjMDA3N2IzKTtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtZ3JhZGllbnQobGluZWFy
LDAgMCwwIDEwMCUsZnJvbSgjMDhjKSx0bygjMDA3N2IzKSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0
LWxpbmVhci1ncmFkaWVudCh0b3AsIzA4YywjMDA3N2IzKTtiYWNrZ3JvdW5kLWltYWdlOi1vLWxpbmVh
ci1ncmFkaWVudCh0b3AsIzA4YywjMDA3N2IzKTtiYWNrZ3JvdW5kLWltYWdlOmxpbmVhci1ncmFkaWVu
dCh0byBib3R0b20sIzA4YywjMDA3N2IzKTtiYWNrZ3JvdW5kLXJlcGVhdDpyZXBlYXQteDtvdXRsaW5l
OjA7ZmlsdGVyOnByb2dpZDpEWEltYWdlVHJhbnNmb3JtLk1pY3Jvc29mdC5ncmFkaWVudChzdGFydENv
bG9yc3RyPScjZmYwMDg4Y2MnLGVuZENvbG9yc3RyPScjZmYwMDc3YjMnLEdyYWRpZW50VHlwZT0wKX0u
ZHJvcGRvd24tbWVudT4uZGlzYWJsZWQ+YSwuZHJvcGRvd24tbWVudT4uZGlzYWJsZWQ+YTpob3Zlciwu
ZHJvcGRvd24tbWVudT4uZGlzYWJsZWQ+YTpmb2N1c3tjb2xvcjojOTk5fS5kcm9wZG93bi1tZW51Pi5k
aXNhYmxlZD5hOmhvdmVyLC5kcm9wZG93bi1tZW51Pi5kaXNhYmxlZD5hOmZvY3Vze3RleHQtZGVjb3Jh
dGlvbjpub25lO2N1cnNvcjpkZWZhdWx0O2JhY2tncm91bmQtY29sb3I6dHJhbnNwYXJlbnQ7YmFja2dy
b3VuZC1pbWFnZTpub25lO2ZpbHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3Jh
ZGllbnQoZW5hYmxlZD1mYWxzZSl9Lm9wZW57KnotaW5kZXg6MTAwMH0ub3Blbj4uZHJvcGRvd24tbWVu
dXtkaXNwbGF5OmJsb2NrfS5wdWxsLXJpZ2h0Pi5kcm9wZG93bi1tZW51e3JpZ2h0OjA7bGVmdDphdXRv
fS5kcm9wdXAgLmNhcmV0LC5uYXZiYXItZml4ZWQtYm90dG9tIC5kcm9wZG93biAuY2FyZXR7Ym9yZGVy
LXRvcDowO2JvcmRlci1ib3R0b206NHB4IHNvbGlkICMwMDA7Y29udGVudDoiIn0uZHJvcHVwIC5kcm9w
ZG93bi1tZW51LC5uYXZiYXItZml4ZWQtYm90dG9tIC5kcm9wZG93biAuZHJvcGRvd24tbWVudXt0b3A6
YXV0bztib3R0b206MTAwJTttYXJnaW4tYm90dG9tOjFweH0uZHJvcGRvd24tc3VibWVudXtwb3NpdGlv
bjpyZWxhdGl2ZX0uZHJvcGRvd24tc3VibWVudT4uZHJvcGRvd24tbWVudXt0b3A6MDtsZWZ0OjEwMCU7
bWFyZ2luLXRvcDotNnB4O21hcmdpbi1sZWZ0Oi0xcHg7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjAgNnB4
IDZweCA2cHg7LW1vei1ib3JkZXItcmFkaXVzOjAgNnB4IDZweCA2cHg7Ym9yZGVyLXJhZGl1czowIDZw
eCA2cHggNnB4fS5kcm9wZG93bi1zdWJtZW51OmhvdmVyPi5kcm9wZG93bi1tZW51e2Rpc3BsYXk6Ymxv
Y2t9LmRyb3B1cCAuZHJvcGRvd24tc3VibWVudT4uZHJvcGRvd24tbWVudXt0b3A6YXV0bztib3R0b206
MDttYXJnaW4tdG9wOjA7bWFyZ2luLWJvdHRvbTotMnB4Oy13ZWJraXQtYm9yZGVyLXJhZGl1czo1cHgg
NXB4IDVweCAwOy1tb3otYm9yZGVyLXJhZGl1czo1cHggNXB4IDVweCAwO2JvcmRlci1yYWRpdXM6NXB4
IDVweCA1cHggMH0uZHJvcGRvd24tc3VibWVudT5hOmFmdGVye2Rpc3BsYXk6YmxvY2s7ZmxvYXQ6cmln
aHQ7d2lkdGg6MDtoZWlnaHQ6MDttYXJnaW4tdG9wOjVweDttYXJnaW4tcmlnaHQ6LTEwcHg7Ym9yZGVy
LWNvbG9yOnRyYW5zcGFyZW50O2JvcmRlci1sZWZ0LWNvbG9yOiNjY2M7Ym9yZGVyLXN0eWxlOnNvbGlk
O2JvcmRlci13aWR0aDo1cHggMCA1cHggNXB4O2NvbnRlbnQ6IiAifS5kcm9wZG93bi1zdWJtZW51Omhv
dmVyPmE6YWZ0ZXJ7Ym9yZGVyLWxlZnQtY29sb3I6I2ZmZn0uZHJvcGRvd24tc3VibWVudS5wdWxsLWxl
ZnR7ZmxvYXQ6bm9uZX0uZHJvcGRvd24tc3VibWVudS5wdWxsLWxlZnQ+LmRyb3Bkb3duLW1lbnV7bGVm
dDotMTAwJTttYXJnaW4tbGVmdDoxMHB4Oy13ZWJraXQtYm9yZGVyLXJhZGl1czo2cHggMCA2cHggNnB4
Oy1tb3otYm9yZGVyLXJhZGl1czo2cHggMCA2cHggNnB4O2JvcmRlci1yYWRpdXM6NnB4IDAgNnB4IDZw
eH0uZHJvcGRvd24gLmRyb3Bkb3duLW1lbnUgLm5hdi1oZWFkZXJ7cGFkZGluZy1yaWdodDoyMHB4O3Bh
ZGRpbmctbGVmdDoyMHB4fS50eXBlYWhlYWR7ei1pbmRleDoxMDUxO21hcmdpbi10b3A6MnB4Oy13ZWJr
aXQtYm9yZGVyLXJhZGl1czo0cHg7LW1vei1ib3JkZXItcmFkaXVzOjRweDtib3JkZXItcmFkaXVzOjRw
eH0ud2VsbHttaW4taGVpZ2h0OjIwcHg7cGFkZGluZzoxOXB4O21hcmdpbi1ib3R0b206MjBweDtiYWNr
Z3JvdW5kLWNvbG9yOiNmNWY1ZjU7Ym9yZGVyOjFweCBzb2xpZCAjZTNlM2UzOy13ZWJraXQtYm9yZGVy
LXJhZGl1czo0cHg7LW1vei1ib3JkZXItcmFkaXVzOjRweDtib3JkZXItcmFkaXVzOjRweDstd2Via2l0
LWJveC1zaGFkb3c6aW5zZXQgMCAxcHggMXB4IHJnYmEoMCwwLDAsMC4wNSk7LW1vei1ib3gtc2hhZG93
Omluc2V0IDAgMXB4IDFweCByZ2JhKDAsMCwwLDAuMDUpO2JveC1zaGFkb3c6aW5zZXQgMCAxcHggMXB4
IHJnYmEoMCwwLDAsMC4wNSl9LndlbGwgYmxvY2txdW90ZXtib3JkZXItY29sb3I6I2RkZDtib3JkZXIt
Y29sb3I6cmdiYSgwLDAsMCwwLjE1KX0ud2VsbC1sYXJnZXtwYWRkaW5nOjI0cHg7LXdlYmtpdC1ib3Jk
ZXItcmFkaXVzOjZweDstbW96LWJvcmRlci1yYWRpdXM6NnB4O2JvcmRlci1yYWRpdXM6NnB4fS53ZWxs
LXNtYWxse3BhZGRpbmc6OXB4Oy13ZWJraXQtYm9yZGVyLXJhZGl1czozcHg7LW1vei1ib3JkZXItcmFk
aXVzOjNweDtib3JkZXItcmFkaXVzOjNweH0uZmFkZXtvcGFjaXR5OjA7LXdlYmtpdC10cmFuc2l0aW9u
Om9wYWNpdHkgLjE1cyBsaW5lYXI7LW1vei10cmFuc2l0aW9uOm9wYWNpdHkgLjE1cyBsaW5lYXI7LW8t
dHJhbnNpdGlvbjpvcGFjaXR5IC4xNXMgbGluZWFyO3RyYW5zaXRpb246b3BhY2l0eSAuMTVzIGxpbmVh
cn0uZmFkZS5pbntvcGFjaXR5OjF9LmNvbGxhcHNle3Bvc2l0aW9uOnJlbGF0aXZlO2hlaWdodDowO292
ZXJmbG93OmhpZGRlbjstd2Via2l0LXRyYW5zaXRpb246aGVpZ2h0IC4zNXMgZWFzZTstbW96LXRyYW5z
aXRpb246aGVpZ2h0IC4zNXMgZWFzZTstby10cmFuc2l0aW9uOmhlaWdodCAuMzVzIGVhc2U7dHJhbnNp
dGlvbjpoZWlnaHQgLjM1cyBlYXNlfS5jb2xsYXBzZS5pbntoZWlnaHQ6YXV0b30uY2xvc2V7ZmxvYXQ6
cmlnaHQ7Zm9udC1zaXplOjIwcHg7Zm9udC13ZWlnaHQ6Ym9sZDtsaW5lLWhlaWdodDoyMHB4O2NvbG9y
OiMwMDA7dGV4dC1zaGFkb3c6MCAxcHggMCAjZmZmO29wYWNpdHk6LjI7ZmlsdGVyOmFscGhhKG9wYWNp
dHk9MjApfS5jbG9zZTpob3ZlciwuY2xvc2U6Zm9jdXN7Y29sb3I6IzAwMDt0ZXh0LWRlY29yYXRpb246
bm9uZTtjdXJzb3I6cG9pbnRlcjtvcGFjaXR5Oi40O2ZpbHRlcjphbHBoYShvcGFjaXR5PTQwKX1idXR0
b24uY2xvc2V7cGFkZGluZzowO2N1cnNvcjpwb2ludGVyO2JhY2tncm91bmQ6dHJhbnNwYXJlbnQ7Ym9y
ZGVyOjA7LXdlYmtpdC1hcHBlYXJhbmNlOm5vbmV9LmJ0bntkaXNwbGF5OmlubGluZS1ibG9jazsqZGlz
cGxheTppbmxpbmU7cGFkZGluZzo0cHggMTJweDttYXJnaW4tYm90dG9tOjA7Km1hcmdpbi1sZWZ0Oi4z
ZW07Zm9udC1zaXplOjE0cHg7bGluZS1oZWlnaHQ6MjBweDtjb2xvcjojMzMzO3RleHQtYWxpZ246Y2Vu
dGVyO3RleHQtc2hhZG93OjAgMXB4IDFweCByZ2JhKDI1NSwyNTUsMjU1LDAuNzUpO3ZlcnRpY2FsLWFs
aWduOm1pZGRsZTtjdXJzb3I6cG9pbnRlcjtiYWNrZ3JvdW5kLWNvbG9yOiNmNWY1ZjU7KmJhY2tncm91
bmQtY29sb3I6I2U2ZTZlNjtiYWNrZ3JvdW5kLWltYWdlOi1tb3otbGluZWFyLWdyYWRpZW50KHRvcCwj
ZmZmLCNlNmU2ZTYpO2JhY2tncm91bmQtaW1hZ2U6LXdlYmtpdC1ncmFkaWVudChsaW5lYXIsMCAwLDAg
MTAwJSxmcm9tKCNmZmYpLHRvKCNlNmU2ZTYpKTtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtbGluZWFy
LWdyYWRpZW50KHRvcCwjZmZmLCNlNmU2ZTYpO2JhY2tncm91bmQtaW1hZ2U6LW8tbGluZWFyLWdyYWRp
ZW50KHRvcCwjZmZmLCNlNmU2ZTYpO2JhY2tncm91bmQtaW1hZ2U6bGluZWFyLWdyYWRpZW50KHRvIGJv
dHRvbSwjZmZmLCNlNmU2ZTYpO2JhY2tncm91bmQtcmVwZWF0OnJlcGVhdC14O2JvcmRlcjoxcHggc29s
aWQgI2NjYzsqYm9yZGVyOjA7Ym9yZGVyLWNvbG9yOiNlNmU2ZTYgI2U2ZTZlNiAjYmZiZmJmO2JvcmRl
ci1jb2xvcjpyZ2JhKDAsMCwwLDAuMSkgcmdiYSgwLDAsMCwwLjEpIHJnYmEoMCwwLDAsMC4yNSk7Ym9y
ZGVyLWJvdHRvbS1jb2xvcjojYjNiM2IzOy13ZWJraXQtYm9yZGVyLXJhZGl1czo0cHg7LW1vei1ib3Jk
ZXItcmFkaXVzOjRweDtib3JkZXItcmFkaXVzOjRweDtmaWx0ZXI6cHJvZ2lkOkRYSW1hZ2VUcmFuc2Zv
cm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9JyNmZmZmZmZmZicsZW5kQ29sb3JzdHI9
JyNmZmU2ZTZlNicsR3JhZGllbnRUeXBlPTApO2ZpbHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5zZm9ybS5N
aWNyb3NvZnQuZ3JhZGllbnQoZW5hYmxlZD1mYWxzZSk7Knpvb206MTstd2Via2l0LWJveC1zaGFkb3c6
aW5zZXQgMCAxcHggMCByZ2JhKDI1NSwyNTUsMjU1LDAuMiksMCAxcHggMnB4IHJnYmEoMCwwLDAsMC4w
NSk7LW1vei1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjIpLDAgMXB4
IDJweCByZ2JhKDAsMCwwLDAuMDUpO2JveC1zaGFkb3c6aW5zZXQgMCAxcHggMCByZ2JhKDI1NSwyNTUs
MjU1LDAuMiksMCAxcHggMnB4IHJnYmEoMCwwLDAsMC4wNSl9LmJ0bjpob3ZlciwuYnRuOmZvY3VzLC5i
dG46YWN0aXZlLC5idG4uYWN0aXZlLC5idG4uZGlzYWJsZWQsLmJ0bltkaXNhYmxlZF17Y29sb3I6IzMz
MztiYWNrZ3JvdW5kLWNvbG9yOiNlNmU2ZTY7KmJhY2tncm91bmQtY29sb3I6I2Q5ZDlkOX0uYnRuOmFj
dGl2ZSwuYnRuLmFjdGl2ZXtiYWNrZ3JvdW5kLWNvbG9yOiNjY2MgXDl9LmJ0bjpmaXJzdC1jaGlsZHsq
bWFyZ2luLWxlZnQ6MH0uYnRuOmhvdmVyLC5idG46Zm9jdXN7Y29sb3I6IzMzMzt0ZXh0LWRlY29yYXRp
b246bm9uZTtiYWNrZ3JvdW5kLXBvc2l0aW9uOjAgLTE1cHg7LXdlYmtpdC10cmFuc2l0aW9uOmJhY2tn
cm91bmQtcG9zaXRpb24gLjFzIGxpbmVhcjstbW96LXRyYW5zaXRpb246YmFja2dyb3VuZC1wb3NpdGlv
biAuMXMgbGluZWFyOy1vLXRyYW5zaXRpb246YmFja2dyb3VuZC1wb3NpdGlvbiAuMXMgbGluZWFyO3Ry
YW5zaXRpb246YmFja2dyb3VuZC1wb3NpdGlvbiAuMXMgbGluZWFyfS5idG46Zm9jdXN7b3V0bGluZTp0
aGluIGRvdHRlZCAjMzMzO291dGxpbmU6NXB4IGF1dG8gLXdlYmtpdC1mb2N1cy1yaW5nLWNvbG9yO291
dGxpbmUtb2Zmc2V0Oi0ycHh9LmJ0bi5hY3RpdmUsLmJ0bjphY3RpdmV7YmFja2dyb3VuZC1pbWFnZTpu
b25lO291dGxpbmU6MDstd2Via2l0LWJveC1zaGFkb3c6aW5zZXQgMCAycHggNHB4IHJnYmEoMCwwLDAs
MC4xNSksMCAxcHggMnB4IHJnYmEoMCwwLDAsMC4wNSk7LW1vei1ib3gtc2hhZG93Omluc2V0IDAgMnB4
IDRweCByZ2JhKDAsMCwwLDAuMTUpLDAgMXB4IDJweCByZ2JhKDAsMCwwLDAuMDUpO2JveC1zaGFkb3c6
aW5zZXQgMCAycHggNHB4IHJnYmEoMCwwLDAsMC4xNSksMCAxcHggMnB4IHJnYmEoMCwwLDAsMC4wNSl9
LmJ0bi5kaXNhYmxlZCwuYnRuW2Rpc2FibGVkXXtjdXJzb3I6ZGVmYXVsdDtiYWNrZ3JvdW5kLWltYWdl
Om5vbmU7b3BhY2l0eTouNjU7ZmlsdGVyOmFscGhhKG9wYWNpdHk9NjUpOy13ZWJraXQtYm94LXNoYWRv
dzpub25lOy1tb3otYm94LXNoYWRvdzpub25lO2JveC1zaGFkb3c6bm9uZX0uYnRuLWxhcmdle3BhZGRp
bmc6MTFweCAxOXB4O2ZvbnQtc2l6ZToxNy41cHg7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjZweDstbW96
LWJvcmRlci1yYWRpdXM6NnB4O2JvcmRlci1yYWRpdXM6NnB4fS5idG4tbGFyZ2UgW2NsYXNzXj0iaWNv
bi0iXSwuYnRuLWxhcmdlIFtjbGFzcyo9IiBpY29uLSJde21hcmdpbi10b3A6NHB4fS5idG4tc21hbGx7
cGFkZGluZzoycHggMTBweDtmb250LXNpemU6MTEuOXB4Oy13ZWJraXQtYm9yZGVyLXJhZGl1czozcHg7
LW1vei1ib3JkZXItcmFkaXVzOjNweDtib3JkZXItcmFkaXVzOjNweH0uYnRuLXNtYWxsIFtjbGFzc149
Imljb24tIl0sLmJ0bi1zbWFsbCBbY2xhc3MqPSIgaWNvbi0iXXttYXJnaW4tdG9wOjB9LmJ0bi1taW5p
IFtjbGFzc149Imljb24tIl0sLmJ0bi1taW5pIFtjbGFzcyo9IiBpY29uLSJde21hcmdpbi10b3A6LTFw
eH0uYnRuLW1pbml7cGFkZGluZzowIDZweDtmb250LXNpemU6MTAuNXB4Oy13ZWJraXQtYm9yZGVyLXJh
ZGl1czozcHg7LW1vei1ib3JkZXItcmFkaXVzOjNweDtib3JkZXItcmFkaXVzOjNweH0uYnRuLWJsb2Nr
e2Rpc3BsYXk6YmxvY2s7d2lkdGg6MTAwJTtwYWRkaW5nLXJpZ2h0OjA7cGFkZGluZy1sZWZ0OjA7LXdl
YmtpdC1ib3gtc2l6aW5nOmJvcmRlci1ib3g7LW1vei1ib3gtc2l6aW5nOmJvcmRlci1ib3g7Ym94LXNp
emluZzpib3JkZXItYm94fS5idG4tYmxvY2srLmJ0bi1ibG9ja3ttYXJnaW4tdG9wOjVweH1pbnB1dFt0
eXBlPSJzdWJtaXQiXS5idG4tYmxvY2ssaW5wdXRbdHlwZT0icmVzZXQiXS5idG4tYmxvY2ssaW5wdXRb
dHlwZT0iYnV0dG9uIl0uYnRuLWJsb2Nre3dpZHRoOjEwMCV9LmJ0bi1wcmltYXJ5LmFjdGl2ZSwuYnRu
LXdhcm5pbmcuYWN0aXZlLC5idG4tZGFuZ2VyLmFjdGl2ZSwuYnRuLXN1Y2Nlc3MuYWN0aXZlLC5idG4t
aW5mby5hY3RpdmUsLmJ0bi1pbnZlcnNlLmFjdGl2ZXtjb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuNzUp
fS5idG4tcHJpbWFyeXtjb2xvcjojZmZmO3RleHQtc2hhZG93OjAgLTFweCAwIHJnYmEoMCwwLDAsMC4y
NSk7YmFja2dyb3VuZC1jb2xvcjojMDA2ZGNjOypiYWNrZ3JvdW5kLWNvbG9yOiMwNGM7YmFja2dyb3Vu
ZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVudCh0b3AsIzA4YywjMDRjKTtiYWNrZ3JvdW5kLWltYWdl
Oi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjMDhjKSx0bygjMDRjKSk7YmFj
a2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsIzA4YywjMDRjKTtiYWNrZ3Jv
dW5kLWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsIzA4YywjMDRjKTtiYWNrZ3JvdW5kLWltYWdl
OmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sIzA4YywjMDRjKTtiYWNrZ3JvdW5kLXJlcGVhdDpyZXBl
YXQteDtib3JkZXItY29sb3I6IzA0YyAjMDRjICMwMDJhODA7Ym9yZGVyLWNvbG9yOnJnYmEoMCwwLDAs
MC4xKSByZ2JhKDAsMCwwLDAuMSkgcmdiYSgwLDAsMCwwLjI1KTtmaWx0ZXI6cHJvZ2lkOkRYSW1hZ2VU
cmFuc2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9JyNmZjAwODhjYycsZW5kQ29s
b3JzdHI9JyNmZjAwNDRjYycsR3JhZGllbnRUeXBlPTApO2ZpbHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5z
Zm9ybS5NaWNyb3NvZnQuZ3JhZGllbnQoZW5hYmxlZD1mYWxzZSl9LmJ0bi1wcmltYXJ5OmhvdmVyLC5i
dG4tcHJpbWFyeTpmb2N1cywuYnRuLXByaW1hcnk6YWN0aXZlLC5idG4tcHJpbWFyeS5hY3RpdmUsLmJ0
bi1wcmltYXJ5LmRpc2FibGVkLC5idG4tcHJpbWFyeVtkaXNhYmxlZF17Y29sb3I6I2ZmZjtiYWNrZ3Jv
dW5kLWNvbG9yOiMwNGM7KmJhY2tncm91bmQtY29sb3I6IzAwM2JiM30uYnRuLXByaW1hcnk6YWN0aXZl
LC5idG4tcHJpbWFyeS5hY3RpdmV7YmFja2dyb3VuZC1jb2xvcjojMDM5IFw5fS5idG4td2FybmluZ3tj
b2xvcjojZmZmO3RleHQtc2hhZG93OjAgLTFweCAwIHJnYmEoMCwwLDAsMC4yNSk7YmFja2dyb3VuZC1j
b2xvcjojZmFhNzMyOypiYWNrZ3JvdW5kLWNvbG9yOiNmODk0MDY7YmFja2dyb3VuZC1pbWFnZTotbW96
LWxpbmVhci1ncmFkaWVudCh0b3AsI2ZiYjQ1MCwjZjg5NDA2KTtiYWNrZ3JvdW5kLWltYWdlOi13ZWJr
aXQtZ3JhZGllbnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjZmJiNDUwKSx0bygjZjg5NDA2KSk7YmFj
a2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsI2ZiYjQ1MCwjZjg5NDA2KTti
YWNrZ3JvdW5kLWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsI2ZiYjQ1MCwjZjg5NDA2KTtiYWNr
Z3JvdW5kLWltYWdlOmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sI2ZiYjQ1MCwjZjg5NDA2KTtiYWNr
Z3JvdW5kLXJlcGVhdDpyZXBlYXQteDtib3JkZXItY29sb3I6I2Y4OTQwNiAjZjg5NDA2ICNhZDY3MDQ7
Ym9yZGVyLWNvbG9yOnJnYmEoMCwwLDAsMC4xKSByZ2JhKDAsMCwwLDAuMSkgcmdiYSgwLDAsMCwwLjI1
KTtmaWx0ZXI6cHJvZ2lkOkRYSW1hZ2VUcmFuc2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29s
b3JzdHI9JyNmZmZiYjQ1MCcsZW5kQ29sb3JzdHI9JyNmZmY4OTQwNicsR3JhZGllbnRUeXBlPTApO2Zp
bHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3JhZGllbnQoZW5hYmxlZD1mYWxz
ZSl9LmJ0bi13YXJuaW5nOmhvdmVyLC5idG4td2FybmluZzpmb2N1cywuYnRuLXdhcm5pbmc6YWN0aXZl
LC5idG4td2FybmluZy5hY3RpdmUsLmJ0bi13YXJuaW5nLmRpc2FibGVkLC5idG4td2FybmluZ1tkaXNh
YmxlZF17Y29sb3I6I2ZmZjtiYWNrZ3JvdW5kLWNvbG9yOiNmODk0MDY7KmJhY2tncm91bmQtY29sb3I6
I2RmODUwNX0uYnRuLXdhcm5pbmc6YWN0aXZlLC5idG4td2FybmluZy5hY3RpdmV7YmFja2dyb3VuZC1j
b2xvcjojYzY3NjA1IFw5fS5idG4tZGFuZ2Vye2NvbG9yOiNmZmY7dGV4dC1zaGFkb3c6MCAtMXB4IDAg
cmdiYSgwLDAsMCwwLjI1KTtiYWNrZ3JvdW5kLWNvbG9yOiNkYTRmNDk7KmJhY2tncm91bmQtY29sb3I6
I2JkMzYyZjtiYWNrZ3JvdW5kLWltYWdlOi1tb3otbGluZWFyLWdyYWRpZW50KHRvcCwjZWU1ZjViLCNi
ZDM2MmYpO2JhY2tncm91bmQtaW1hZ2U6LXdlYmtpdC1ncmFkaWVudChsaW5lYXIsMCAwLDAgMTAwJSxm
cm9tKCNlZTVmNWIpLHRvKCNiZDM2MmYpKTtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtbGluZWFyLWdy
YWRpZW50KHRvcCwjZWU1ZjViLCNiZDM2MmYpO2JhY2tncm91bmQtaW1hZ2U6LW8tbGluZWFyLWdyYWRp
ZW50KHRvcCwjZWU1ZjViLCNiZDM2MmYpO2JhY2tncm91bmQtaW1hZ2U6bGluZWFyLWdyYWRpZW50KHRv
IGJvdHRvbSwjZWU1ZjViLCNiZDM2MmYpO2JhY2tncm91bmQtcmVwZWF0OnJlcGVhdC14O2JvcmRlci1j
b2xvcjojYmQzNjJmICNiZDM2MmYgIzgwMjQyMDtib3JkZXItY29sb3I6cmdiYSgwLDAsMCwwLjEpIHJn
YmEoMCwwLDAsMC4xKSByZ2JhKDAsMCwwLDAuMjUpO2ZpbHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5zZm9y
bS5NaWNyb3NvZnQuZ3JhZGllbnQoc3RhcnRDb2xvcnN0cj0nI2ZmZWU1ZjViJyxlbmRDb2xvcnN0cj0n
I2ZmYmQzNjJmJyxHcmFkaWVudFR5cGU9MCk7ZmlsdGVyOnByb2dpZDpEWEltYWdlVHJhbnNmb3JtLk1p
Y3Jvc29mdC5ncmFkaWVudChlbmFibGVkPWZhbHNlKX0uYnRuLWRhbmdlcjpob3ZlciwuYnRuLWRhbmdl
cjpmb2N1cywuYnRuLWRhbmdlcjphY3RpdmUsLmJ0bi1kYW5nZXIuYWN0aXZlLC5idG4tZGFuZ2VyLmRp
c2FibGVkLC5idG4tZGFuZ2VyW2Rpc2FibGVkXXtjb2xvcjojZmZmO2JhY2tncm91bmQtY29sb3I6I2Jk
MzYyZjsqYmFja2dyb3VuZC1jb2xvcjojYTkzMDJhfS5idG4tZGFuZ2VyOmFjdGl2ZSwuYnRuLWRhbmdl
ci5hY3RpdmV7YmFja2dyb3VuZC1jb2xvcjojOTQyYTI1IFw5fS5idG4tc3VjY2Vzc3tjb2xvcjojZmZm
O3RleHQtc2hhZG93OjAgLTFweCAwIHJnYmEoMCwwLDAsMC4yNSk7YmFja2dyb3VuZC1jb2xvcjojNWJi
NzViOypiYWNrZ3JvdW5kLWNvbG9yOiM1MWEzNTE7YmFja2dyb3VuZC1pbWFnZTotbW96LWxpbmVhci1n
cmFkaWVudCh0b3AsIzYyYzQ2MiwjNTFhMzUxKTtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtZ3JhZGll
bnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjNjJjNDYyKSx0bygjNTFhMzUxKSk7YmFja2dyb3VuZC1p
bWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsIzYyYzQ2MiwjNTFhMzUxKTtiYWNrZ3JvdW5k
LWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsIzYyYzQ2MiwjNTFhMzUxKTtiYWNrZ3JvdW5kLWlt
YWdlOmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sIzYyYzQ2MiwjNTFhMzUxKTtiYWNrZ3JvdW5kLXJl
cGVhdDpyZXBlYXQteDtib3JkZXItY29sb3I6IzUxYTM1MSAjNTFhMzUxICMzODcwMzg7Ym9yZGVyLWNv
bG9yOnJnYmEoMCwwLDAsMC4xKSByZ2JhKDAsMCwwLDAuMSkgcmdiYSgwLDAsMCwwLjI1KTtmaWx0ZXI6
cHJvZ2lkOkRYSW1hZ2VUcmFuc2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9JyNm
ZjYyYzQ2MicsZW5kQ29sb3JzdHI9JyNmZjUxYTM1MScsR3JhZGllbnRUeXBlPTApO2ZpbHRlcjpwcm9n
aWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3JhZGllbnQoZW5hYmxlZD1mYWxzZSl9LmJ0bi1z
dWNjZXNzOmhvdmVyLC5idG4tc3VjY2Vzczpmb2N1cywuYnRuLXN1Y2Nlc3M6YWN0aXZlLC5idG4tc3Vj
Y2Vzcy5hY3RpdmUsLmJ0bi1zdWNjZXNzLmRpc2FibGVkLC5idG4tc3VjY2Vzc1tkaXNhYmxlZF17Y29s
b3I6I2ZmZjtiYWNrZ3JvdW5kLWNvbG9yOiM1MWEzNTE7KmJhY2tncm91bmQtY29sb3I6IzQ5OTI0OX0u
YnRuLXN1Y2Nlc3M6YWN0aXZlLC5idG4tc3VjY2Vzcy5hY3RpdmV7YmFja2dyb3VuZC1jb2xvcjojNDA4
MTQwIFw5fS5idG4taW5mb3tjb2xvcjojZmZmO3RleHQtc2hhZG93OjAgLTFweCAwIHJnYmEoMCwwLDAs
MC4yNSk7YmFja2dyb3VuZC1jb2xvcjojNDlhZmNkOypiYWNrZ3JvdW5kLWNvbG9yOiMyZjk2YjQ7YmFj
a2dyb3VuZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVudCh0b3AsIzViYzBkZSwjMmY5NmI0KTtiYWNr
Z3JvdW5kLWltYWdlOi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjNWJjMGRl
KSx0bygjMmY5NmI0KSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3As
IzViYzBkZSwjMmY5NmI0KTtiYWNrZ3JvdW5kLWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsIzVi
YzBkZSwjMmY5NmI0KTtiYWNrZ3JvdW5kLWltYWdlOmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sIzVi
YzBkZSwjMmY5NmI0KTtiYWNrZ3JvdW5kLXJlcGVhdDpyZXBlYXQteDtib3JkZXItY29sb3I6IzJmOTZi
NCAjMmY5NmI0ICMxZjYzNzc7Ym9yZGVyLWNvbG9yOnJnYmEoMCwwLDAsMC4xKSByZ2JhKDAsMCwwLDAu
MSkgcmdiYSgwLDAsMCwwLjI1KTtmaWx0ZXI6cHJvZ2lkOkRYSW1hZ2VUcmFuc2Zvcm0uTWljcm9zb2Z0
LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9JyNmZjViYzBkZScsZW5kQ29sb3JzdHI9JyNmZjJmOTZiNCcs
R3JhZGllbnRUeXBlPTApO2ZpbHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3Jh
ZGllbnQoZW5hYmxlZD1mYWxzZSl9LmJ0bi1pbmZvOmhvdmVyLC5idG4taW5mbzpmb2N1cywuYnRuLWlu
Zm86YWN0aXZlLC5idG4taW5mby5hY3RpdmUsLmJ0bi1pbmZvLmRpc2FibGVkLC5idG4taW5mb1tkaXNh
YmxlZF17Y29sb3I6I2ZmZjtiYWNrZ3JvdW5kLWNvbG9yOiMyZjk2YjQ7KmJhY2tncm91bmQtY29sb3I6
IzJhODVhMH0uYnRuLWluZm86YWN0aXZlLC5idG4taW5mby5hY3RpdmV7YmFja2dyb3VuZC1jb2xvcjoj
MjQ3NDhjIFw5fS5idG4taW52ZXJzZXtjb2xvcjojZmZmO3RleHQtc2hhZG93OjAgLTFweCAwIHJnYmEo
MCwwLDAsMC4yNSk7YmFja2dyb3VuZC1jb2xvcjojMzYzNjM2OypiYWNrZ3JvdW5kLWNvbG9yOiMyMjI7
YmFja2dyb3VuZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVudCh0b3AsIzQ0NCwjMjIyKTtiYWNrZ3Jv
dW5kLWltYWdlOi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjNDQ0KSx0bygj
MjIyKSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsIzQ0NCwjMjIy
KTtiYWNrZ3JvdW5kLWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsIzQ0NCwjMjIyKTtiYWNrZ3Jv
dW5kLWltYWdlOmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sIzQ0NCwjMjIyKTtiYWNrZ3JvdW5kLXJl
cGVhdDpyZXBlYXQteDtib3JkZXItY29sb3I6IzIyMiAjMjIyICMwMDA7Ym9yZGVyLWNvbG9yOnJnYmEo
MCwwLDAsMC4xKSByZ2JhKDAsMCwwLDAuMSkgcmdiYSgwLDAsMCwwLjI1KTtmaWx0ZXI6cHJvZ2lkOkRY
SW1hZ2VUcmFuc2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9JyNmZjQ0NDQ0NCcs
ZW5kQ29sb3JzdHI9JyNmZjIyMjIyMicsR3JhZGllbnRUeXBlPTApO2ZpbHRlcjpwcm9naWQ6RFhJbWFn
ZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3JhZGllbnQoZW5hYmxlZD1mYWxzZSl9LmJ0bi1pbnZlcnNlOmhv
dmVyLC5idG4taW52ZXJzZTpmb2N1cywuYnRuLWludmVyc2U6YWN0aXZlLC5idG4taW52ZXJzZS5hY3Rp
dmUsLmJ0bi1pbnZlcnNlLmRpc2FibGVkLC5idG4taW52ZXJzZVtkaXNhYmxlZF17Y29sb3I6I2ZmZjti
YWNrZ3JvdW5kLWNvbG9yOiMyMjI7KmJhY2tncm91bmQtY29sb3I6IzE1MTUxNX0uYnRuLWludmVyc2U6
YWN0aXZlLC5idG4taW52ZXJzZS5hY3RpdmV7YmFja2dyb3VuZC1jb2xvcjojMDgwODA4IFw5fWJ1dHRv
bi5idG4saW5wdXRbdHlwZT0ic3VibWl0Il0uYnRueypwYWRkaW5nLXRvcDozcHg7KnBhZGRpbmctYm90
dG9tOjNweH1idXR0b24uYnRuOjotbW96LWZvY3VzLWlubmVyLGlucHV0W3R5cGU9InN1Ym1pdCJdLmJ0
bjo6LW1vei1mb2N1cy1pbm5lcntwYWRkaW5nOjA7Ym9yZGVyOjB9YnV0dG9uLmJ0bi5idG4tbGFyZ2Us
aW5wdXRbdHlwZT0ic3VibWl0Il0uYnRuLmJ0bi1sYXJnZXsqcGFkZGluZy10b3A6N3B4OypwYWRkaW5n
LWJvdHRvbTo3cHh9YnV0dG9uLmJ0bi5idG4tc21hbGwsaW5wdXRbdHlwZT0ic3VibWl0Il0uYnRuLmJ0
bi1zbWFsbHsqcGFkZGluZy10b3A6M3B4OypwYWRkaW5nLWJvdHRvbTozcHh9YnV0dG9uLmJ0bi5idG4t
bWluaSxpbnB1dFt0eXBlPSJzdWJtaXQiXS5idG4uYnRuLW1pbml7KnBhZGRpbmctdG9wOjFweDsqcGFk
ZGluZy1ib3R0b206MXB4fS5idG4tbGluaywuYnRuLWxpbms6YWN0aXZlLC5idG4tbGlua1tkaXNhYmxl
ZF17YmFja2dyb3VuZC1jb2xvcjp0cmFuc3BhcmVudDtiYWNrZ3JvdW5kLWltYWdlOm5vbmU7LXdlYmtp
dC1ib3gtc2hhZG93Om5vbmU7LW1vei1ib3gtc2hhZG93Om5vbmU7Ym94LXNoYWRvdzpub25lfS5idG4t
bGlua3tjb2xvcjojMDhjO2N1cnNvcjpwb2ludGVyO2JvcmRlci1jb2xvcjp0cmFuc3BhcmVudDstd2Vi
a2l0LWJvcmRlci1yYWRpdXM6MDstbW96LWJvcmRlci1yYWRpdXM6MDtib3JkZXItcmFkaXVzOjB9LmJ0
bi1saW5rOmhvdmVyLC5idG4tbGluazpmb2N1c3tjb2xvcjojMDA1NTgwO3RleHQtZGVjb3JhdGlvbjp1
bmRlcmxpbmU7YmFja2dyb3VuZC1jb2xvcjp0cmFuc3BhcmVudH0uYnRuLWxpbmtbZGlzYWJsZWRdOmhv
dmVyLC5idG4tbGlua1tkaXNhYmxlZF06Zm9jdXN7Y29sb3I6IzMzMzt0ZXh0LWRlY29yYXRpb246bm9u
ZX0uYnRuLWdyb3Vwe3Bvc2l0aW9uOnJlbGF0aXZlO2Rpc3BsYXk6aW5saW5lLWJsb2NrOypkaXNwbGF5
OmlubGluZTsqbWFyZ2luLWxlZnQ6LjNlbTtmb250LXNpemU6MDt3aGl0ZS1zcGFjZTpub3dyYXA7dmVy
dGljYWwtYWxpZ246bWlkZGxlOyp6b29tOjF9LmJ0bi1ncm91cDpmaXJzdC1jaGlsZHsqbWFyZ2luLWxl
ZnQ6MH0uYnRuLWdyb3VwKy5idG4tZ3JvdXB7bWFyZ2luLWxlZnQ6NXB4fS5idG4tdG9vbGJhcnttYXJn
aW4tdG9wOjEwcHg7bWFyZ2luLWJvdHRvbToxMHB4O2ZvbnQtc2l6ZTowfS5idG4tdG9vbGJhcj4uYnRu
Ky5idG4sLmJ0bi10b29sYmFyPi5idG4tZ3JvdXArLmJ0biwuYnRuLXRvb2xiYXI+LmJ0bisuYnRuLWdy
b3Vwe21hcmdpbi1sZWZ0OjVweH0uYnRuLWdyb3VwPi5idG57cG9zaXRpb246cmVsYXRpdmU7LXdlYmtp
dC1ib3JkZXItcmFkaXVzOjA7LW1vei1ib3JkZXItcmFkaXVzOjA7Ym9yZGVyLXJhZGl1czowfS5idG4t
Z3JvdXA+LmJ0bisuYnRue21hcmdpbi1sZWZ0Oi0xcHh9LmJ0bi1ncm91cD4uYnRuLC5idG4tZ3JvdXA+
LmRyb3Bkb3duLW1lbnUsLmJ0bi1ncm91cD4ucG9wb3Zlcntmb250LXNpemU6MTRweH0uYnRuLWdyb3Vw
Pi5idG4tbWluaXtmb250LXNpemU6MTAuNXB4fS5idG4tZ3JvdXA+LmJ0bi1zbWFsbHtmb250LXNpemU6
MTEuOXB4fS5idG4tZ3JvdXA+LmJ0bi1sYXJnZXtmb250LXNpemU6MTcuNXB4fS5idG4tZ3JvdXA+LmJ0
bjpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDowOy13ZWJraXQtYm9yZGVyLWJvdHRvbS1sZWZ0LXJhZGl1
czo0cHg7Ym9yZGVyLWJvdHRvbS1sZWZ0LXJhZGl1czo0cHg7LXdlYmtpdC1ib3JkZXItdG9wLWxlZnQt
cmFkaXVzOjRweDtib3JkZXItdG9wLWxlZnQtcmFkaXVzOjRweDstbW96LWJvcmRlci1yYWRpdXMtYm90
dG9tbGVmdDo0cHg7LW1vei1ib3JkZXItcmFkaXVzLXRvcGxlZnQ6NHB4fS5idG4tZ3JvdXA+LmJ0bjps
YXN0LWNoaWxkLC5idG4tZ3JvdXA+LmRyb3Bkb3duLXRvZ2dsZXstd2Via2l0LWJvcmRlci10b3Atcmln
aHQtcmFkaXVzOjRweDtib3JkZXItdG9wLXJpZ2h0LXJhZGl1czo0cHg7LXdlYmtpdC1ib3JkZXItYm90
dG9tLXJpZ2h0LXJhZGl1czo0cHg7Ym9yZGVyLWJvdHRvbS1yaWdodC1yYWRpdXM6NHB4Oy1tb3otYm9y
ZGVyLXJhZGl1cy10b3ByaWdodDo0cHg7LW1vei1ib3JkZXItcmFkaXVzLWJvdHRvbXJpZ2h0OjRweH0u
YnRuLWdyb3VwPi5idG4ubGFyZ2U6Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6MDstd2Via2l0LWJvcmRl
ci1ib3R0b20tbGVmdC1yYWRpdXM6NnB4O2JvcmRlci1ib3R0b20tbGVmdC1yYWRpdXM6NnB4Oy13ZWJr
aXQtYm9yZGVyLXRvcC1sZWZ0LXJhZGl1czo2cHg7Ym9yZGVyLXRvcC1sZWZ0LXJhZGl1czo2cHg7LW1v
ei1ib3JkZXItcmFkaXVzLWJvdHRvbWxlZnQ6NnB4Oy1tb3otYm9yZGVyLXJhZGl1cy10b3BsZWZ0OjZw
eH0uYnRuLWdyb3VwPi5idG4ubGFyZ2U6bGFzdC1jaGlsZCwuYnRuLWdyb3VwPi5sYXJnZS5kcm9wZG93
bi10b2dnbGV7LXdlYmtpdC1ib3JkZXItdG9wLXJpZ2h0LXJhZGl1czo2cHg7Ym9yZGVyLXRvcC1yaWdo
dC1yYWRpdXM6NnB4Oy13ZWJraXQtYm9yZGVyLWJvdHRvbS1yaWdodC1yYWRpdXM6NnB4O2JvcmRlci1i
b3R0b20tcmlnaHQtcmFkaXVzOjZweDstbW96LWJvcmRlci1yYWRpdXMtdG9wcmlnaHQ6NnB4Oy1tb3ot
Ym9yZGVyLXJhZGl1cy1ib3R0b21yaWdodDo2cHh9LmJ0bi1ncm91cD4uYnRuOmhvdmVyLC5idG4tZ3Jv
dXA+LmJ0bjpmb2N1cywuYnRuLWdyb3VwPi5idG46YWN0aXZlLC5idG4tZ3JvdXA+LmJ0bi5hY3RpdmV7
ei1pbmRleDoyfS5idG4tZ3JvdXAgLmRyb3Bkb3duLXRvZ2dsZTphY3RpdmUsLmJ0bi1ncm91cC5vcGVu
IC5kcm9wZG93bi10b2dnbGV7b3V0bGluZTowfS5idG4tZ3JvdXA+LmJ0bisuZHJvcGRvd24tdG9nZ2xl
eypwYWRkaW5nLXRvcDo1cHg7cGFkZGluZy1yaWdodDo4cHg7KnBhZGRpbmctYm90dG9tOjVweDtwYWRk
aW5nLWxlZnQ6OHB4Oy13ZWJraXQtYm94LXNoYWRvdzppbnNldCAxcHggMCAwIHJnYmEoMjU1LDI1NSwy
NTUsMC4xMjUpLGluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjIpLDAgMXB4IDJweCByZ2Jh
KDAsMCwwLDAuMDUpOy1tb3otYm94LXNoYWRvdzppbnNldCAxcHggMCAwIHJnYmEoMjU1LDI1NSwyNTUs
MC4xMjUpLGluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjIpLDAgMXB4IDJweCByZ2JhKDAs
MCwwLDAuMDUpO2JveC1zaGFkb3c6aW5zZXQgMXB4IDAgMCByZ2JhKDI1NSwyNTUsMjU1LDAuMTI1KSxp
bnNldCAwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4yKSwwIDFweCAycHggcmdiYSgwLDAsMCwwLjA1
KX0uYnRuLWdyb3VwPi5idG4tbWluaSsuZHJvcGRvd24tdG9nZ2xleypwYWRkaW5nLXRvcDoycHg7cGFk
ZGluZy1yaWdodDo1cHg7KnBhZGRpbmctYm90dG9tOjJweDtwYWRkaW5nLWxlZnQ6NXB4fS5idG4tZ3Jv
dXA+LmJ0bi1zbWFsbCsuZHJvcGRvd24tdG9nZ2xleypwYWRkaW5nLXRvcDo1cHg7KnBhZGRpbmctYm90
dG9tOjRweH0uYnRuLWdyb3VwPi5idG4tbGFyZ2UrLmRyb3Bkb3duLXRvZ2dsZXsqcGFkZGluZy10b3A6
N3B4O3BhZGRpbmctcmlnaHQ6MTJweDsqcGFkZGluZy1ib3R0b206N3B4O3BhZGRpbmctbGVmdDoxMnB4
fS5idG4tZ3JvdXAub3BlbiAuZHJvcGRvd24tdG9nZ2xle2JhY2tncm91bmQtaW1hZ2U6bm9uZTstd2Vi
a2l0LWJveC1zaGFkb3c6aW5zZXQgMCAycHggNHB4IHJnYmEoMCwwLDAsMC4xNSksMCAxcHggMnB4IHJn
YmEoMCwwLDAsMC4wNSk7LW1vei1ib3gtc2hhZG93Omluc2V0IDAgMnB4IDRweCByZ2JhKDAsMCwwLDAu
MTUpLDAgMXB4IDJweCByZ2JhKDAsMCwwLDAuMDUpO2JveC1zaGFkb3c6aW5zZXQgMCAycHggNHB4IHJn
YmEoMCwwLDAsMC4xNSksMCAxcHggMnB4IHJnYmEoMCwwLDAsMC4wNSl9LmJ0bi1ncm91cC5vcGVuIC5i
dG4uZHJvcGRvd24tdG9nZ2xle2JhY2tncm91bmQtY29sb3I6I2U2ZTZlNn0uYnRuLWdyb3VwLm9wZW4g
LmJ0bi1wcmltYXJ5LmRyb3Bkb3duLXRvZ2dsZXtiYWNrZ3JvdW5kLWNvbG9yOiMwNGN9LmJ0bi1ncm91
cC5vcGVuIC5idG4td2FybmluZy5kcm9wZG93bi10b2dnbGV7YmFja2dyb3VuZC1jb2xvcjojZjg5NDA2
fS5idG4tZ3JvdXAub3BlbiAuYnRuLWRhbmdlci5kcm9wZG93bi10b2dnbGV7YmFja2dyb3VuZC1jb2xv
cjojYmQzNjJmfS5idG4tZ3JvdXAub3BlbiAuYnRuLXN1Y2Nlc3MuZHJvcGRvd24tdG9nZ2xle2JhY2tn
cm91bmQtY29sb3I6IzUxYTM1MX0uYnRuLWdyb3VwLm9wZW4gLmJ0bi1pbmZvLmRyb3Bkb3duLXRvZ2ds
ZXtiYWNrZ3JvdW5kLWNvbG9yOiMyZjk2YjR9LmJ0bi1ncm91cC5vcGVuIC5idG4taW52ZXJzZS5kcm9w
ZG93bi10b2dnbGV7YmFja2dyb3VuZC1jb2xvcjojMjIyfS5idG4gLmNhcmV0e21hcmdpbi10b3A6OHB4
O21hcmdpbi1sZWZ0OjB9LmJ0bi1sYXJnZSAuY2FyZXR7bWFyZ2luLXRvcDo2cHh9LmJ0bi1sYXJnZSAu
Y2FyZXR7Ym9yZGVyLXRvcC13aWR0aDo1cHg7Ym9yZGVyLXJpZ2h0LXdpZHRoOjVweDtib3JkZXItbGVm
dC13aWR0aDo1cHh9LmJ0bi1taW5pIC5jYXJldCwuYnRuLXNtYWxsIC5jYXJldHttYXJnaW4tdG9wOjhw
eH0uZHJvcHVwIC5idG4tbGFyZ2UgLmNhcmV0e2JvcmRlci1ib3R0b20td2lkdGg6NXB4fS5idG4tcHJp
bWFyeSAuY2FyZXQsLmJ0bi13YXJuaW5nIC5jYXJldCwuYnRuLWRhbmdlciAuY2FyZXQsLmJ0bi1pbmZv
IC5jYXJldCwuYnRuLXN1Y2Nlc3MgLmNhcmV0LC5idG4taW52ZXJzZSAuY2FyZXR7Ym9yZGVyLXRvcC1j
b2xvcjojZmZmO2JvcmRlci1ib3R0b20tY29sb3I6I2ZmZn0uYnRuLWdyb3VwLXZlcnRpY2Fse2Rpc3Bs
YXk6aW5saW5lLWJsb2NrOypkaXNwbGF5OmlubGluZTsqem9vbToxfS5idG4tZ3JvdXAtdmVydGljYWw+
LmJ0bntkaXNwbGF5OmJsb2NrO2Zsb2F0Om5vbmU7bWF4LXdpZHRoOjEwMCU7LXdlYmtpdC1ib3JkZXIt
cmFkaXVzOjA7LW1vei1ib3JkZXItcmFkaXVzOjA7Ym9yZGVyLXJhZGl1czowfS5idG4tZ3JvdXAtdmVy
dGljYWw+LmJ0bisuYnRue21hcmdpbi10b3A6LTFweDttYXJnaW4tbGVmdDowfS5idG4tZ3JvdXAtdmVy
dGljYWw+LmJ0bjpmaXJzdC1jaGlsZHstd2Via2l0LWJvcmRlci1yYWRpdXM6NHB4IDRweCAwIDA7LW1v
ei1ib3JkZXItcmFkaXVzOjRweCA0cHggMCAwO2JvcmRlci1yYWRpdXM6NHB4IDRweCAwIDB9LmJ0bi1n
cm91cC12ZXJ0aWNhbD4uYnRuOmxhc3QtY2hpbGR7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjAgMCA0cHgg
NHB4Oy1tb3otYm9yZGVyLXJhZGl1czowIDAgNHB4IDRweDtib3JkZXItcmFkaXVzOjAgMCA0cHggNHB4
fS5idG4tZ3JvdXAtdmVydGljYWw+LmJ0bi1sYXJnZTpmaXJzdC1jaGlsZHstd2Via2l0LWJvcmRlci1y
YWRpdXM6NnB4IDZweCAwIDA7LW1vei1ib3JkZXItcmFkaXVzOjZweCA2cHggMCAwO2JvcmRlci1yYWRp
dXM6NnB4IDZweCAwIDB9LmJ0bi1ncm91cC12ZXJ0aWNhbD4uYnRuLWxhcmdlOmxhc3QtY2hpbGR7LXdl
YmtpdC1ib3JkZXItcmFkaXVzOjAgMCA2cHggNnB4Oy1tb3otYm9yZGVyLXJhZGl1czowIDAgNnB4IDZw
eDtib3JkZXItcmFkaXVzOjAgMCA2cHggNnB4fS5hbGVydHtwYWRkaW5nOjhweCAzNXB4IDhweCAxNHB4
O21hcmdpbi1ib3R0b206MjBweDt0ZXh0LXNoYWRvdzowIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC41
KTtiYWNrZ3JvdW5kLWNvbG9yOiNmY2Y4ZTM7Ym9yZGVyOjFweCBzb2xpZCAjZmJlZWQ1Oy13ZWJraXQt
Ym9yZGVyLXJhZGl1czo0cHg7LW1vei1ib3JkZXItcmFkaXVzOjRweDtib3JkZXItcmFkaXVzOjRweH0u
YWxlcnQsLmFsZXJ0IGg0e2NvbG9yOiNjMDk4NTN9LmFsZXJ0IGg0e21hcmdpbjowfS5hbGVydCAuY2xv
c2V7cG9zaXRpb246cmVsYXRpdmU7dG9wOi0ycHg7cmlnaHQ6LTIxcHg7bGluZS1oZWlnaHQ6MjBweH0u
YWxlcnQtc3VjY2Vzc3tjb2xvcjojNDY4ODQ3O2JhY2tncm91bmQtY29sb3I6I2RmZjBkODtib3JkZXIt
Y29sb3I6I2Q2ZTljNn0uYWxlcnQtc3VjY2VzcyBoNHtjb2xvcjojNDY4ODQ3fS5hbGVydC1kYW5nZXIs
LmFsZXJ0LWVycm9ye2NvbG9yOiNiOTRhNDg7YmFja2dyb3VuZC1jb2xvcjojZjJkZWRlO2JvcmRlci1j
b2xvcjojZWVkM2Q3fS5hbGVydC1kYW5nZXIgaDQsLmFsZXJ0LWVycm9yIGg0e2NvbG9yOiNiOTRhNDh9
LmFsZXJ0LWluZm97Y29sb3I6IzNhODdhZDtiYWNrZ3JvdW5kLWNvbG9yOiNkOWVkZjc7Ym9yZGVyLWNv
bG9yOiNiY2U4ZjF9LmFsZXJ0LWluZm8gaDR7Y29sb3I6IzNhODdhZH0uYWxlcnQtYmxvY2t7cGFkZGlu
Zy10b3A6MTRweDtwYWRkaW5nLWJvdHRvbToxNHB4fS5hbGVydC1ibG9jaz5wLC5hbGVydC1ibG9jaz51
bHttYXJnaW4tYm90dG9tOjB9LmFsZXJ0LWJsb2NrIHArcHttYXJnaW4tdG9wOjVweH0ubmF2e21hcmdp
bi1ib3R0b206MjBweDttYXJnaW4tbGVmdDowO2xpc3Qtc3R5bGU6bm9uZX0ubmF2PmxpPmF7ZGlzcGxh
eTpibG9ja30ubmF2PmxpPmE6aG92ZXIsLm5hdj5saT5hOmZvY3Vze3RleHQtZGVjb3JhdGlvbjpub25l
O2JhY2tncm91bmQtY29sb3I6I2VlZX0ubmF2PmxpPmE+aW1ne21heC13aWR0aDpub25lfS5uYXY+LnB1
bGwtcmlnaHR7ZmxvYXQ6cmlnaHR9Lm5hdi1oZWFkZXJ7ZGlzcGxheTpibG9jaztwYWRkaW5nOjNweCAx
NXB4O2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2VpZ2h0OmJvbGQ7bGluZS1oZWlnaHQ6MjBweDtjb2xvcjoj
OTk5O3RleHQtc2hhZG93OjAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjUpO3RleHQtdHJhbnNmb3Jt
OnVwcGVyY2FzZX0ubmF2IGxpKy5uYXYtaGVhZGVye21hcmdpbi10b3A6OXB4fS5uYXYtbGlzdHtwYWRk
aW5nLXJpZ2h0OjE1cHg7cGFkZGluZy1sZWZ0OjE1cHg7bWFyZ2luLWJvdHRvbTowfS5uYXYtbGlzdD5s
aT5hLC5uYXYtbGlzdCAubmF2LWhlYWRlcnttYXJnaW4tcmlnaHQ6LTE1cHg7bWFyZ2luLWxlZnQ6LTE1
cHg7dGV4dC1zaGFkb3c6MCAxcHggMCByZ2JhKDI1NSwyNTUsMjU1LDAuNSl9Lm5hdi1saXN0PmxpPmF7
cGFkZGluZzozcHggMTVweH0ubmF2LWxpc3Q+LmFjdGl2ZT5hLC5uYXYtbGlzdD4uYWN0aXZlPmE6aG92
ZXIsLm5hdi1saXN0Pi5hY3RpdmU+YTpmb2N1c3tjb2xvcjojZmZmO3RleHQtc2hhZG93OjAgLTFweCAw
IHJnYmEoMCwwLDAsMC4yKTtiYWNrZ3JvdW5kLWNvbG9yOiMwOGN9Lm5hdi1saXN0IFtjbGFzc149Imlj
b24tIl0sLm5hdi1saXN0IFtjbGFzcyo9IiBpY29uLSJde21hcmdpbi1yaWdodDoycHh9Lm5hdi1saXN0
IC5kaXZpZGVyeyp3aWR0aDoxMDAlO2hlaWdodDoxcHg7bWFyZ2luOjlweCAxcHg7Km1hcmdpbjotNXB4
IDAgNXB4O292ZXJmbG93OmhpZGRlbjtiYWNrZ3JvdW5kLWNvbG9yOiNlNWU1ZTU7Ym9yZGVyLWJvdHRv
bToxcHggc29saWQgI2ZmZn0ubmF2LXRhYnMsLm5hdi1waWxsc3sqem9vbToxfS5uYXYtdGFiczpiZWZv
cmUsLm5hdi1waWxsczpiZWZvcmUsLm5hdi10YWJzOmFmdGVyLC5uYXYtcGlsbHM6YWZ0ZXJ7ZGlzcGxh
eTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9Lm5hdi10YWJzOmFmdGVyLC5uYXYtcGlsbHM6
YWZ0ZXJ7Y2xlYXI6Ym90aH0ubmF2LXRhYnM+bGksLm5hdi1waWxscz5saXtmbG9hdDpsZWZ0fS5uYXYt
dGFicz5saT5hLC5uYXYtcGlsbHM+bGk+YXtwYWRkaW5nLXJpZ2h0OjEycHg7cGFkZGluZy1sZWZ0OjEy
cHg7bWFyZ2luLXJpZ2h0OjJweDtsaW5lLWhlaWdodDoxNHB4fS5uYXYtdGFic3tib3JkZXItYm90dG9t
OjFweCBzb2xpZCAjZGRkfS5uYXYtdGFicz5saXttYXJnaW4tYm90dG9tOi0xcHh9Lm5hdi10YWJzPmxp
PmF7cGFkZGluZy10b3A6OHB4O3BhZGRpbmctYm90dG9tOjhweDtsaW5lLWhlaWdodDoyMHB4O2JvcmRl
cjoxcHggc29saWQgdHJhbnNwYXJlbnQ7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjRweCA0cHggMCAwOy1t
b3otYm9yZGVyLXJhZGl1czo0cHggNHB4IDAgMDtib3JkZXItcmFkaXVzOjRweCA0cHggMCAwfS5uYXYt
dGFicz5saT5hOmhvdmVyLC5uYXYtdGFicz5saT5hOmZvY3Vze2JvcmRlci1jb2xvcjojZWVlICNlZWUg
I2RkZH0ubmF2LXRhYnM+LmFjdGl2ZT5hLC5uYXYtdGFicz4uYWN0aXZlPmE6aG92ZXIsLm5hdi10YWJz
Pi5hY3RpdmU+YTpmb2N1c3tjb2xvcjojNTU1O2N1cnNvcjpkZWZhdWx0O2JhY2tncm91bmQtY29sb3I6
I2ZmZjtib3JkZXI6MXB4IHNvbGlkICNkZGQ7Ym9yZGVyLWJvdHRvbS1jb2xvcjp0cmFuc3BhcmVudH0u
bmF2LXBpbGxzPmxpPmF7cGFkZGluZy10b3A6OHB4O3BhZGRpbmctYm90dG9tOjhweDttYXJnaW4tdG9w
OjJweDttYXJnaW4tYm90dG9tOjJweDstd2Via2l0LWJvcmRlci1yYWRpdXM6NXB4Oy1tb3otYm9yZGVy
LXJhZGl1czo1cHg7Ym9yZGVyLXJhZGl1czo1cHh9Lm5hdi1waWxscz4uYWN0aXZlPmEsLm5hdi1waWxs
cz4uYWN0aXZlPmE6aG92ZXIsLm5hdi1waWxscz4uYWN0aXZlPmE6Zm9jdXN7Y29sb3I6I2ZmZjtiYWNr
Z3JvdW5kLWNvbG9yOiMwOGN9Lm5hdi1zdGFja2VkPmxpe2Zsb2F0Om5vbmV9Lm5hdi1zdGFja2VkPmxp
PmF7bWFyZ2luLXJpZ2h0OjB9Lm5hdi10YWJzLm5hdi1zdGFja2Vke2JvcmRlci1ib3R0b206MH0ubmF2
LXRhYnMubmF2LXN0YWNrZWQ+bGk+YXtib3JkZXI6MXB4IHNvbGlkICNkZGQ7LXdlYmtpdC1ib3JkZXIt
cmFkaXVzOjA7LW1vei1ib3JkZXItcmFkaXVzOjA7Ym9yZGVyLXJhZGl1czowfS5uYXYtdGFicy5uYXYt
c3RhY2tlZD5saTpmaXJzdC1jaGlsZD5hey13ZWJraXQtYm9yZGVyLXRvcC1yaWdodC1yYWRpdXM6NHB4
O2JvcmRlci10b3AtcmlnaHQtcmFkaXVzOjRweDstd2Via2l0LWJvcmRlci10b3AtbGVmdC1yYWRpdXM6
NHB4O2JvcmRlci10b3AtbGVmdC1yYWRpdXM6NHB4Oy1tb3otYm9yZGVyLXJhZGl1cy10b3ByaWdodDo0
cHg7LW1vei1ib3JkZXItcmFkaXVzLXRvcGxlZnQ6NHB4fS5uYXYtdGFicy5uYXYtc3RhY2tlZD5saTps
YXN0LWNoaWxkPmF7LXdlYmtpdC1ib3JkZXItYm90dG9tLXJpZ2h0LXJhZGl1czo0cHg7Ym9yZGVyLWJv
dHRvbS1yaWdodC1yYWRpdXM6NHB4Oy13ZWJraXQtYm9yZGVyLWJvdHRvbS1sZWZ0LXJhZGl1czo0cHg7
Ym9yZGVyLWJvdHRvbS1sZWZ0LXJhZGl1czo0cHg7LW1vei1ib3JkZXItcmFkaXVzLWJvdHRvbXJpZ2h0
OjRweDstbW96LWJvcmRlci1yYWRpdXMtYm90dG9tbGVmdDo0cHh9Lm5hdi10YWJzLm5hdi1zdGFja2Vk
PmxpPmE6aG92ZXIsLm5hdi10YWJzLm5hdi1zdGFja2VkPmxpPmE6Zm9jdXN7ei1pbmRleDoyO2JvcmRl
ci1jb2xvcjojZGRkfS5uYXYtcGlsbHMubmF2LXN0YWNrZWQ+bGk+YXttYXJnaW4tYm90dG9tOjNweH0u
bmF2LXBpbGxzLm5hdi1zdGFja2VkPmxpOmxhc3QtY2hpbGQ+YXttYXJnaW4tYm90dG9tOjFweH0ubmF2
LXRhYnMgLmRyb3Bkb3duLW1lbnV7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjAgMCA2cHggNnB4Oy1tb3ot
Ym9yZGVyLXJhZGl1czowIDAgNnB4IDZweDtib3JkZXItcmFkaXVzOjAgMCA2cHggNnB4fS5uYXYtcGls
bHMgLmRyb3Bkb3duLW1lbnV7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjZweDstbW96LWJvcmRlci1yYWRp
dXM6NnB4O2JvcmRlci1yYWRpdXM6NnB4fS5uYXYgLmRyb3Bkb3duLXRvZ2dsZSAuY2FyZXR7bWFyZ2lu
LXRvcDo2cHg7Ym9yZGVyLXRvcC1jb2xvcjojMDhjO2JvcmRlci1ib3R0b20tY29sb3I6IzA4Y30ubmF2
IC5kcm9wZG93bi10b2dnbGU6aG92ZXIgLmNhcmV0LC5uYXYgLmRyb3Bkb3duLXRvZ2dsZTpmb2N1cyAu
Y2FyZXR7Ym9yZGVyLXRvcC1jb2xvcjojMDA1NTgwO2JvcmRlci1ib3R0b20tY29sb3I6IzAwNTU4MH0u
bmF2LXRhYnMgLmRyb3Bkb3duLXRvZ2dsZSAuY2FyZXR7bWFyZ2luLXRvcDo4cHh9Lm5hdiAuYWN0aXZl
IC5kcm9wZG93bi10b2dnbGUgLmNhcmV0e2JvcmRlci10b3AtY29sb3I6I2ZmZjtib3JkZXItYm90dG9t
LWNvbG9yOiNmZmZ9Lm5hdi10YWJzIC5hY3RpdmUgLmRyb3Bkb3duLXRvZ2dsZSAuY2FyZXR7Ym9yZGVy
LXRvcC1jb2xvcjojNTU1O2JvcmRlci1ib3R0b20tY29sb3I6IzU1NX0ubmF2Pi5kcm9wZG93bi5hY3Rp
dmU+YTpob3ZlciwubmF2Pi5kcm9wZG93bi5hY3RpdmU+YTpmb2N1c3tjdXJzb3I6cG9pbnRlcn0ubmF2
LXRhYnMgLm9wZW4gLmRyb3Bkb3duLXRvZ2dsZSwubmF2LXBpbGxzIC5vcGVuIC5kcm9wZG93bi10b2dn
bGUsLm5hdj5saS5kcm9wZG93bi5vcGVuLmFjdGl2ZT5hOmhvdmVyLC5uYXY+bGkuZHJvcGRvd24ub3Bl
bi5hY3RpdmU+YTpmb2N1c3tjb2xvcjojZmZmO2JhY2tncm91bmQtY29sb3I6Izk5OTtib3JkZXItY29s
b3I6Izk5OX0ubmF2IGxpLmRyb3Bkb3duLm9wZW4gLmNhcmV0LC5uYXYgbGkuZHJvcGRvd24ub3Blbi5h
Y3RpdmUgLmNhcmV0LC5uYXYgbGkuZHJvcGRvd24ub3BlbiBhOmhvdmVyIC5jYXJldCwubmF2IGxpLmRy
b3Bkb3duLm9wZW4gYTpmb2N1cyAuY2FyZXR7Ym9yZGVyLXRvcC1jb2xvcjojZmZmO2JvcmRlci1ib3R0
b20tY29sb3I6I2ZmZjtvcGFjaXR5OjE7ZmlsdGVyOmFscGhhKG9wYWNpdHk9MTAwKX0udGFicy1zdGFj
a2VkIC5vcGVuPmE6aG92ZXIsLnRhYnMtc3RhY2tlZCAub3Blbj5hOmZvY3Vze2JvcmRlci1jb2xvcjoj
OTk5fS50YWJiYWJsZXsqem9vbToxfS50YWJiYWJsZTpiZWZvcmUsLnRhYmJhYmxlOmFmdGVye2Rpc3Bs
YXk6dGFibGU7bGluZS1oZWlnaHQ6MDtjb250ZW50OiIifS50YWJiYWJsZTphZnRlcntjbGVhcjpib3Ro
fS50YWItY29udGVudHtvdmVyZmxvdzphdXRvfS50YWJzLWJlbG93Pi5uYXYtdGFicywudGFicy1yaWdo
dD4ubmF2LXRhYnMsLnRhYnMtbGVmdD4ubmF2LXRhYnN7Ym9yZGVyLWJvdHRvbTowfS50YWItY29udGVu
dD4udGFiLXBhbmUsLnBpbGwtY29udGVudD4ucGlsbC1wYW5le2Rpc3BsYXk6bm9uZX0udGFiLWNvbnRl
bnQ+LmFjdGl2ZSwucGlsbC1jb250ZW50Pi5hY3RpdmV7ZGlzcGxheTpibG9ja30udGFicy1iZWxvdz4u
bmF2LXRhYnN7Ym9yZGVyLXRvcDoxcHggc29saWQgI2RkZH0udGFicy1iZWxvdz4ubmF2LXRhYnM+bGl7
bWFyZ2luLXRvcDotMXB4O21hcmdpbi1ib3R0b206MH0udGFicy1iZWxvdz4ubmF2LXRhYnM+bGk+YXst
d2Via2l0LWJvcmRlci1yYWRpdXM6MCAwIDRweCA0cHg7LW1vei1ib3JkZXItcmFkaXVzOjAgMCA0cHgg
NHB4O2JvcmRlci1yYWRpdXM6MCAwIDRweCA0cHh9LnRhYnMtYmVsb3c+Lm5hdi10YWJzPmxpPmE6aG92
ZXIsLnRhYnMtYmVsb3c+Lm5hdi10YWJzPmxpPmE6Zm9jdXN7Ym9yZGVyLXRvcC1jb2xvcjojZGRkO2Jv
cmRlci1ib3R0b20tY29sb3I6dHJhbnNwYXJlbnR9LnRhYnMtYmVsb3c+Lm5hdi10YWJzPi5hY3RpdmU+
YSwudGFicy1iZWxvdz4ubmF2LXRhYnM+LmFjdGl2ZT5hOmhvdmVyLC50YWJzLWJlbG93Pi5uYXYtdGFi
cz4uYWN0aXZlPmE6Zm9jdXN7Ym9yZGVyLWNvbG9yOnRyYW5zcGFyZW50ICNkZGQgI2RkZCAjZGRkfS50
YWJzLWxlZnQ+Lm5hdi10YWJzPmxpLC50YWJzLXJpZ2h0Pi5uYXYtdGFicz5saXtmbG9hdDpub25lfS50
YWJzLWxlZnQ+Lm5hdi10YWJzPmxpPmEsLnRhYnMtcmlnaHQ+Lm5hdi10YWJzPmxpPmF7bWluLXdpZHRo
Ojc0cHg7bWFyZ2luLXJpZ2h0OjA7bWFyZ2luLWJvdHRvbTozcHh9LnRhYnMtbGVmdD4ubmF2LXRhYnN7
ZmxvYXQ6bGVmdDttYXJnaW4tcmlnaHQ6MTlweDtib3JkZXItcmlnaHQ6MXB4IHNvbGlkICNkZGR9LnRh
YnMtbGVmdD4ubmF2LXRhYnM+bGk+YXttYXJnaW4tcmlnaHQ6LTFweDstd2Via2l0LWJvcmRlci1yYWRp
dXM6NHB4IDAgMCA0cHg7LW1vei1ib3JkZXItcmFkaXVzOjRweCAwIDAgNHB4O2JvcmRlci1yYWRpdXM6
NHB4IDAgMCA0cHh9LnRhYnMtbGVmdD4ubmF2LXRhYnM+bGk+YTpob3ZlciwudGFicy1sZWZ0Pi5uYXYt
dGFicz5saT5hOmZvY3Vze2JvcmRlci1jb2xvcjojZWVlICNkZGQgI2VlZSAjZWVlfS50YWJzLWxlZnQ+
Lm5hdi10YWJzIC5hY3RpdmU+YSwudGFicy1sZWZ0Pi5uYXYtdGFicyAuYWN0aXZlPmE6aG92ZXIsLnRh
YnMtbGVmdD4ubmF2LXRhYnMgLmFjdGl2ZT5hOmZvY3Vze2JvcmRlci1jb2xvcjojZGRkIHRyYW5zcGFy
ZW50ICNkZGQgI2RkZDsqYm9yZGVyLXJpZ2h0LWNvbG9yOiNmZmZ9LnRhYnMtcmlnaHQ+Lm5hdi10YWJz
e2Zsb2F0OnJpZ2h0O21hcmdpbi1sZWZ0OjE5cHg7Ym9yZGVyLWxlZnQ6MXB4IHNvbGlkICNkZGR9LnRh
YnMtcmlnaHQ+Lm5hdi10YWJzPmxpPmF7bWFyZ2luLWxlZnQ6LTFweDstd2Via2l0LWJvcmRlci1yYWRp
dXM6MCA0cHggNHB4IDA7LW1vei1ib3JkZXItcmFkaXVzOjAgNHB4IDRweCAwO2JvcmRlci1yYWRpdXM6
MCA0cHggNHB4IDB9LnRhYnMtcmlnaHQ+Lm5hdi10YWJzPmxpPmE6aG92ZXIsLnRhYnMtcmlnaHQ+Lm5h
di10YWJzPmxpPmE6Zm9jdXN7Ym9yZGVyLWNvbG9yOiNlZWUgI2VlZSAjZWVlICNkZGR9LnRhYnMtcmln
aHQ+Lm5hdi10YWJzIC5hY3RpdmU+YSwudGFicy1yaWdodD4ubmF2LXRhYnMgLmFjdGl2ZT5hOmhvdmVy
LC50YWJzLXJpZ2h0Pi5uYXYtdGFicyAuYWN0aXZlPmE6Zm9jdXN7Ym9yZGVyLWNvbG9yOiNkZGQgI2Rk
ZCAjZGRkIHRyYW5zcGFyZW50Oypib3JkZXItbGVmdC1jb2xvcjojZmZmfS5uYXY+LmRpc2FibGVkPmF7
Y29sb3I6Izk5OX0ubmF2Pi5kaXNhYmxlZD5hOmhvdmVyLC5uYXY+LmRpc2FibGVkPmE6Zm9jdXN7dGV4
dC1kZWNvcmF0aW9uOm5vbmU7Y3Vyc29yOmRlZmF1bHQ7YmFja2dyb3VuZC1jb2xvcjp0cmFuc3BhcmVu
dH0ubmF2YmFyeypwb3NpdGlvbjpyZWxhdGl2ZTsqei1pbmRleDoyO21hcmdpbi1ib3R0b206MjBweDtv
dmVyZmxvdzp2aXNpYmxlfS5uYXZiYXItaW5uZXJ7bWluLWhlaWdodDo0MHB4O3BhZGRpbmctcmlnaHQ6
MjBweDtwYWRkaW5nLWxlZnQ6MjBweDtiYWNrZ3JvdW5kLWNvbG9yOiNmYWZhZmE7YmFja2dyb3VuZC1p
bWFnZTotbW96LWxpbmVhci1ncmFkaWVudCh0b3AsI2ZmZiwjZjJmMmYyKTtiYWNrZ3JvdW5kLWltYWdl
Oi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjZmZmKSx0bygjZjJmMmYyKSk7
YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsI2ZmZiwjZjJmMmYyKTti
YWNrZ3JvdW5kLWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsI2ZmZiwjZjJmMmYyKTtiYWNrZ3Jv
dW5kLWltYWdlOmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sI2ZmZiwjZjJmMmYyKTtiYWNrZ3JvdW5k
LXJlcGVhdDpyZXBlYXQteDtib3JkZXI6MXB4IHNvbGlkICNkNGQ0ZDQ7LXdlYmtpdC1ib3JkZXItcmFk
aXVzOjRweDstbW96LWJvcmRlci1yYWRpdXM6NHB4O2JvcmRlci1yYWRpdXM6NHB4O2ZpbHRlcjpwcm9n
aWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3JhZGllbnQoc3RhcnRDb2xvcnN0cj0nI2ZmZmZm
ZmZmJyxlbmRDb2xvcnN0cj0nI2ZmZjJmMmYyJyxHcmFkaWVudFR5cGU9MCk7Knpvb206MTstd2Via2l0
LWJveC1zaGFkb3c6MCAxcHggNHB4IHJnYmEoMCwwLDAsMC4wNjUpOy1tb3otYm94LXNoYWRvdzowIDFw
eCA0cHggcmdiYSgwLDAsMCwwLjA2NSk7Ym94LXNoYWRvdzowIDFweCA0cHggcmdiYSgwLDAsMCwwLjA2
NSl9Lm5hdmJhci1pbm5lcjpiZWZvcmUsLm5hdmJhci1pbm5lcjphZnRlcntkaXNwbGF5OnRhYmxlO2xp
bmUtaGVpZ2h0OjA7Y29udGVudDoiIn0ubmF2YmFyLWlubmVyOmFmdGVye2NsZWFyOmJvdGh9Lm5hdmJh
ciAuY29udGFpbmVye3dpZHRoOmF1dG99Lm5hdi1jb2xsYXBzZS5jb2xsYXBzZXtoZWlnaHQ6YXV0bztv
dmVyZmxvdzp2aXNpYmxlfS5uYXZiYXIgLmJyYW5ke2Rpc3BsYXk6YmxvY2s7ZmxvYXQ6bGVmdDtwYWRk
aW5nOjEwcHggMjBweCAxMHB4O21hcmdpbi1sZWZ0Oi0yMHB4O2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2Vp
Z2h0OjIwMDtjb2xvcjojNzc3O3RleHQtc2hhZG93OjAgMXB4IDAgI2ZmZn0ubmF2YmFyIC5icmFuZDpo
b3ZlciwubmF2YmFyIC5icmFuZDpmb2N1c3t0ZXh0LWRlY29yYXRpb246bm9uZX0ubmF2YmFyLXRleHR7
bWFyZ2luLWJvdHRvbTowO2xpbmUtaGVpZ2h0OjQwcHg7Y29sb3I6Izc3N30ubmF2YmFyLWxpbmt7Y29s
b3I6Izc3N30ubmF2YmFyLWxpbms6aG92ZXIsLm5hdmJhci1saW5rOmZvY3Vze2NvbG9yOiMzMzN9Lm5h
dmJhciAuZGl2aWRlci12ZXJ0aWNhbHtoZWlnaHQ6NDBweDttYXJnaW46MCA5cHg7Ym9yZGVyLXJpZ2h0
OjFweCBzb2xpZCAjZmZmO2JvcmRlci1sZWZ0OjFweCBzb2xpZCAjZjJmMmYyfS5uYXZiYXIgLmJ0biwu
bmF2YmFyIC5idG4tZ3JvdXB7bWFyZ2luLXRvcDo1cHh9Lm5hdmJhciAuYnRuLWdyb3VwIC5idG4sLm5h
dmJhciAuaW5wdXQtcHJlcGVuZCAuYnRuLC5uYXZiYXIgLmlucHV0LWFwcGVuZCAuYnRuLC5uYXZiYXIg
LmlucHV0LXByZXBlbmQgLmJ0bi1ncm91cCwubmF2YmFyIC5pbnB1dC1hcHBlbmQgLmJ0bi1ncm91cHtt
YXJnaW4tdG9wOjB9Lm5hdmJhci1mb3Jte21hcmdpbi1ib3R0b206MDsqem9vbToxfS5uYXZiYXItZm9y
bTpiZWZvcmUsLm5hdmJhci1mb3JtOmFmdGVye2Rpc3BsYXk6dGFibGU7bGluZS1oZWlnaHQ6MDtjb250
ZW50OiIifS5uYXZiYXItZm9ybTphZnRlcntjbGVhcjpib3RofS5uYXZiYXItZm9ybSBpbnB1dCwubmF2
YmFyLWZvcm0gc2VsZWN0LC5uYXZiYXItZm9ybSAucmFkaW8sLm5hdmJhci1mb3JtIC5jaGVja2JveHtt
YXJnaW4tdG9wOjVweH0ubmF2YmFyLWZvcm0gaW5wdXQsLm5hdmJhci1mb3JtIHNlbGVjdCwubmF2YmFy
LWZvcm0gLmJ0bntkaXNwbGF5OmlubGluZS1ibG9jazttYXJnaW4tYm90dG9tOjB9Lm5hdmJhci1mb3Jt
IGlucHV0W3R5cGU9ImltYWdlIl0sLm5hdmJhci1mb3JtIGlucHV0W3R5cGU9ImNoZWNrYm94Il0sLm5h
dmJhci1mb3JtIGlucHV0W3R5cGU9InJhZGlvIl17bWFyZ2luLXRvcDozcHh9Lm5hdmJhci1mb3JtIC5p
bnB1dC1hcHBlbmQsLm5hdmJhci1mb3JtIC5pbnB1dC1wcmVwZW5ke21hcmdpbi10b3A6NXB4O3doaXRl
LXNwYWNlOm5vd3JhcH0ubmF2YmFyLWZvcm0gLmlucHV0LWFwcGVuZCBpbnB1dCwubmF2YmFyLWZvcm0g
LmlucHV0LXByZXBlbmQgaW5wdXR7bWFyZ2luLXRvcDowfS5uYXZiYXItc2VhcmNoe3Bvc2l0aW9uOnJl
bGF0aXZlO2Zsb2F0OmxlZnQ7bWFyZ2luLXRvcDo1cHg7bWFyZ2luLWJvdHRvbTowfS5uYXZiYXItc2Vh
cmNoIC5zZWFyY2gtcXVlcnl7cGFkZGluZzo0cHggMTRweDttYXJnaW4tYm90dG9tOjA7Zm9udC1mYW1p
bHk6IkhlbHZldGljYSBOZXVlIixIZWx2ZXRpY2EsQXJpYWwsc2Fucy1zZXJpZjtmb250LXNpemU6MTNw
eDtmb250LXdlaWdodDpub3JtYWw7bGluZS1oZWlnaHQ6MTstd2Via2l0LWJvcmRlci1yYWRpdXM6MTVw
eDstbW96LWJvcmRlci1yYWRpdXM6MTVweDtib3JkZXItcmFkaXVzOjE1cHh9Lm5hdmJhci1zdGF0aWMt
dG9we3Bvc2l0aW9uOnN0YXRpYzttYXJnaW4tYm90dG9tOjB9Lm5hdmJhci1zdGF0aWMtdG9wIC5uYXZi
YXItaW5uZXJ7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjA7LW1vei1ib3JkZXItcmFkaXVzOjA7Ym9yZGVy
LXJhZGl1czowfS5uYXZiYXItZml4ZWQtdG9wLC5uYXZiYXItZml4ZWQtYm90dG9te3Bvc2l0aW9uOmZp
eGVkO3JpZ2h0OjA7bGVmdDowO3otaW5kZXg6MTAzMDttYXJnaW4tYm90dG9tOjB9Lm5hdmJhci1maXhl
ZC10b3AgLm5hdmJhci1pbm5lciwubmF2YmFyLXN0YXRpYy10b3AgLm5hdmJhci1pbm5lcntib3JkZXIt
d2lkdGg6MCAwIDFweH0ubmF2YmFyLWZpeGVkLWJvdHRvbSAubmF2YmFyLWlubmVye2JvcmRlci13aWR0
aDoxcHggMCAwfS5uYXZiYXItZml4ZWQtdG9wIC5uYXZiYXItaW5uZXIsLm5hdmJhci1maXhlZC1ib3R0
b20gLm5hdmJhci1pbm5lcntwYWRkaW5nLXJpZ2h0OjA7cGFkZGluZy1sZWZ0OjA7LXdlYmtpdC1ib3Jk
ZXItcmFkaXVzOjA7LW1vei1ib3JkZXItcmFkaXVzOjA7Ym9yZGVyLXJhZGl1czowfS5uYXZiYXItc3Rh
dGljLXRvcCAuY29udGFpbmVyLC5uYXZiYXItZml4ZWQtdG9wIC5jb250YWluZXIsLm5hdmJhci1maXhl
ZC1ib3R0b20gLmNvbnRhaW5lcnt3aWR0aDo5NDBweH0ubmF2YmFyLWZpeGVkLXRvcHt0b3A6MH0ubmF2
YmFyLWZpeGVkLXRvcCAubmF2YmFyLWlubmVyLC5uYXZiYXItc3RhdGljLXRvcCAubmF2YmFyLWlubmVy
ey13ZWJraXQtYm94LXNoYWRvdzowIDFweCAxMHB4IHJnYmEoMCwwLDAsMC4xKTstbW96LWJveC1zaGFk
b3c6MCAxcHggMTBweCByZ2JhKDAsMCwwLDAuMSk7Ym94LXNoYWRvdzowIDFweCAxMHB4IHJnYmEoMCww
LDAsMC4xKX0ubmF2YmFyLWZpeGVkLWJvdHRvbXtib3R0b206MH0ubmF2YmFyLWZpeGVkLWJvdHRvbSAu
bmF2YmFyLWlubmVyey13ZWJraXQtYm94LXNoYWRvdzowIC0xcHggMTBweCByZ2JhKDAsMCwwLDAuMSk7
LW1vei1ib3gtc2hhZG93OjAgLTFweCAxMHB4IHJnYmEoMCwwLDAsMC4xKTtib3gtc2hhZG93OjAgLTFw
eCAxMHB4IHJnYmEoMCwwLDAsMC4xKX0ubmF2YmFyIC5uYXZ7cG9zaXRpb246cmVsYXRpdmU7bGVmdDow
O2Rpc3BsYXk6YmxvY2s7ZmxvYXQ6bGVmdDttYXJnaW46MCAxMHB4IDAgMH0ubmF2YmFyIC5uYXYucHVs
bC1yaWdodHtmbG9hdDpyaWdodDttYXJnaW4tcmlnaHQ6MH0ubmF2YmFyIC5uYXY+bGl7ZmxvYXQ6bGVm
dH0ubmF2YmFyIC5uYXY+bGk+YXtmbG9hdDpub25lO3BhZGRpbmc6MTBweCAxNXB4IDEwcHg7Y29sb3I6
Izc3Nzt0ZXh0LWRlY29yYXRpb246bm9uZTt0ZXh0LXNoYWRvdzowIDFweCAwICNmZmZ9Lm5hdmJhciAu
bmF2IC5kcm9wZG93bi10b2dnbGUgLmNhcmV0e21hcmdpbi10b3A6OHB4fS5uYXZiYXIgLm5hdj5saT5h
OmZvY3VzLC5uYXZiYXIgLm5hdj5saT5hOmhvdmVye2NvbG9yOiMzMzM7dGV4dC1kZWNvcmF0aW9uOm5v
bmU7YmFja2dyb3VuZC1jb2xvcjp0cmFuc3BhcmVudH0ubmF2YmFyIC5uYXY+LmFjdGl2ZT5hLC5uYXZi
YXIgLm5hdj4uYWN0aXZlPmE6aG92ZXIsLm5hdmJhciAubmF2Pi5hY3RpdmU+YTpmb2N1c3tjb2xvcjoj
NTU1O3RleHQtZGVjb3JhdGlvbjpub25lO2JhY2tncm91bmQtY29sb3I6I2U1ZTVlNTstd2Via2l0LWJv
eC1zaGFkb3c6aW5zZXQgMCAzcHggOHB4IHJnYmEoMCwwLDAsMC4xMjUpOy1tb3otYm94LXNoYWRvdzpp
bnNldCAwIDNweCA4cHggcmdiYSgwLDAsMCwwLjEyNSk7Ym94LXNoYWRvdzppbnNldCAwIDNweCA4cHgg
cmdiYSgwLDAsMCwwLjEyNSl9Lm5hdmJhciAuYnRuLW5hdmJhcntkaXNwbGF5Om5vbmU7ZmxvYXQ6cmln
aHQ7cGFkZGluZzo3cHggMTBweDttYXJnaW4tcmlnaHQ6NXB4O21hcmdpbi1sZWZ0OjVweDtjb2xvcjoj
ZmZmO3RleHQtc2hhZG93OjAgLTFweCAwIHJnYmEoMCwwLDAsMC4yNSk7YmFja2dyb3VuZC1jb2xvcjoj
ZWRlZGVkOypiYWNrZ3JvdW5kLWNvbG9yOiNlNWU1ZTU7YmFja2dyb3VuZC1pbWFnZTotbW96LWxpbmVh
ci1ncmFkaWVudCh0b3AsI2YyZjJmMiwjZTVlNWU1KTtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtZ3Jh
ZGllbnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjZjJmMmYyKSx0bygjZTVlNWU1KSk7YmFja2dyb3Vu
ZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsI2YyZjJmMiwjZTVlNWU1KTtiYWNrZ3Jv
dW5kLWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsI2YyZjJmMiwjZTVlNWU1KTtiYWNrZ3JvdW5k
LWltYWdlOmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sI2YyZjJmMiwjZTVlNWU1KTtiYWNrZ3JvdW5k
LXJlcGVhdDpyZXBlYXQteDtib3JkZXItY29sb3I6I2U1ZTVlNSAjZTVlNWU1ICNiZmJmYmY7Ym9yZGVy
LWNvbG9yOnJnYmEoMCwwLDAsMC4xKSByZ2JhKDAsMCwwLDAuMSkgcmdiYSgwLDAsMCwwLjI1KTtmaWx0
ZXI6cHJvZ2lkOkRYSW1hZ2VUcmFuc2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9
JyNmZmYyZjJmMicsZW5kQ29sb3JzdHI9JyNmZmU1ZTVlNScsR3JhZGllbnRUeXBlPTApO2ZpbHRlcjpw
cm9naWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3JhZGllbnQoZW5hYmxlZD1mYWxzZSk7LXdl
YmtpdC1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjEpLDAgMXB4IDAg
cmdiYSgyNTUsMjU1LDI1NSwwLjA3NSk7LW1vei1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDAgcmdiYSgy
NTUsMjU1LDI1NSwwLjEpLDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjA3NSk7Ym94LXNoYWRvdzpp
bnNldCAwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4xKSwwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUs
MC4wNzUpfS5uYXZiYXIgLmJ0bi1uYXZiYXI6aG92ZXIsLm5hdmJhciAuYnRuLW5hdmJhcjpmb2N1cywu
bmF2YmFyIC5idG4tbmF2YmFyOmFjdGl2ZSwubmF2YmFyIC5idG4tbmF2YmFyLmFjdGl2ZSwubmF2YmFy
IC5idG4tbmF2YmFyLmRpc2FibGVkLC5uYXZiYXIgLmJ0bi1uYXZiYXJbZGlzYWJsZWRde2NvbG9yOiNm
ZmY7YmFja2dyb3VuZC1jb2xvcjojZTVlNWU1OypiYWNrZ3JvdW5kLWNvbG9yOiNkOWQ5ZDl9Lm5hdmJh
ciAuYnRuLW5hdmJhcjphY3RpdmUsLm5hdmJhciAuYnRuLW5hdmJhci5hY3RpdmV7YmFja2dyb3VuZC1j
b2xvcjojY2NjIFw5fS5uYXZiYXIgLmJ0bi1uYXZiYXIgLmljb24tYmFye2Rpc3BsYXk6YmxvY2s7d2lk
dGg6MThweDtoZWlnaHQ6MnB4O2JhY2tncm91bmQtY29sb3I6I2Y1ZjVmNTstd2Via2l0LWJvcmRlci1y
YWRpdXM6MXB4Oy1tb3otYm9yZGVyLXJhZGl1czoxcHg7Ym9yZGVyLXJhZGl1czoxcHg7LXdlYmtpdC1i
b3gtc2hhZG93OjAgMXB4IDAgcmdiYSgwLDAsMCwwLjI1KTstbW96LWJveC1zaGFkb3c6MCAxcHggMCBy
Z2JhKDAsMCwwLDAuMjUpO2JveC1zaGFkb3c6MCAxcHggMCByZ2JhKDAsMCwwLDAuMjUpfS5idG4tbmF2
YmFyIC5pY29uLWJhcisuaWNvbi1iYXJ7bWFyZ2luLXRvcDozcHh9Lm5hdmJhciAubmF2PmxpPi5kcm9w
ZG93bi1tZW51OmJlZm9yZXtwb3NpdGlvbjphYnNvbHV0ZTt0b3A6LTdweDtsZWZ0OjlweDtkaXNwbGF5
OmlubGluZS1ibG9jaztib3JkZXItcmlnaHQ6N3B4IHNvbGlkIHRyYW5zcGFyZW50O2JvcmRlci1ib3R0
b206N3B4IHNvbGlkICNjY2M7Ym9yZGVyLWxlZnQ6N3B4IHNvbGlkIHRyYW5zcGFyZW50O2JvcmRlci1i
b3R0b20tY29sb3I6cmdiYSgwLDAsMCwwLjIpO2NvbnRlbnQ6Jyd9Lm5hdmJhciAubmF2PmxpPi5kcm9w
ZG93bi1tZW51OmFmdGVye3Bvc2l0aW9uOmFic29sdXRlO3RvcDotNnB4O2xlZnQ6MTBweDtkaXNwbGF5
OmlubGluZS1ibG9jaztib3JkZXItcmlnaHQ6NnB4IHNvbGlkIHRyYW5zcGFyZW50O2JvcmRlci1ib3R0
b206NnB4IHNvbGlkICNmZmY7Ym9yZGVyLWxlZnQ6NnB4IHNvbGlkIHRyYW5zcGFyZW50O2NvbnRlbnQ6
Jyd9Lm5hdmJhci1maXhlZC1ib3R0b20gLm5hdj5saT4uZHJvcGRvd24tbWVudTpiZWZvcmV7dG9wOmF1
dG87Ym90dG9tOi03cHg7Ym9yZGVyLXRvcDo3cHggc29saWQgI2NjYztib3JkZXItYm90dG9tOjA7Ym9y
ZGVyLXRvcC1jb2xvcjpyZ2JhKDAsMCwwLDAuMil9Lm5hdmJhci1maXhlZC1ib3R0b20gLm5hdj5saT4u
ZHJvcGRvd24tbWVudTphZnRlcnt0b3A6YXV0bztib3R0b206LTZweDtib3JkZXItdG9wOjZweCBzb2xp
ZCAjZmZmO2JvcmRlci1ib3R0b206MH0ubmF2YmFyIC5uYXYgbGkuZHJvcGRvd24+YTpob3ZlciAuY2Fy
ZXQsLm5hdmJhciAubmF2IGxpLmRyb3Bkb3duPmE6Zm9jdXMgLmNhcmV0e2JvcmRlci10b3AtY29sb3I6
IzMzMztib3JkZXItYm90dG9tLWNvbG9yOiMzMzN9Lm5hdmJhciAubmF2IGxpLmRyb3Bkb3duLm9wZW4+
LmRyb3Bkb3duLXRvZ2dsZSwubmF2YmFyIC5uYXYgbGkuZHJvcGRvd24uYWN0aXZlPi5kcm9wZG93bi10
b2dnbGUsLm5hdmJhciAubmF2IGxpLmRyb3Bkb3duLm9wZW4uYWN0aXZlPi5kcm9wZG93bi10b2dnbGV7
Y29sb3I6IzU1NTtiYWNrZ3JvdW5kLWNvbG9yOiNlNWU1ZTV9Lm5hdmJhciAubmF2IGxpLmRyb3Bkb3du
Pi5kcm9wZG93bi10b2dnbGUgLmNhcmV0e2JvcmRlci10b3AtY29sb3I6Izc3Nztib3JkZXItYm90dG9t
LWNvbG9yOiM3Nzd9Lm5hdmJhciAubmF2IGxpLmRyb3Bkb3duLm9wZW4+LmRyb3Bkb3duLXRvZ2dsZSAu
Y2FyZXQsLm5hdmJhciAubmF2IGxpLmRyb3Bkb3duLmFjdGl2ZT4uZHJvcGRvd24tdG9nZ2xlIC5jYXJl
dCwubmF2YmFyIC5uYXYgbGkuZHJvcGRvd24ub3Blbi5hY3RpdmU+LmRyb3Bkb3duLXRvZ2dsZSAuY2Fy
ZXR7Ym9yZGVyLXRvcC1jb2xvcjojNTU1O2JvcmRlci1ib3R0b20tY29sb3I6IzU1NX0ubmF2YmFyIC5w
dWxsLXJpZ2h0PmxpPi5kcm9wZG93bi1tZW51LC5uYXZiYXIgLm5hdj5saT4uZHJvcGRvd24tbWVudS5w
dWxsLXJpZ2h0e3JpZ2h0OjA7bGVmdDphdXRvfS5uYXZiYXIgLnB1bGwtcmlnaHQ+bGk+LmRyb3Bkb3du
LW1lbnU6YmVmb3JlLC5uYXZiYXIgLm5hdj5saT4uZHJvcGRvd24tbWVudS5wdWxsLXJpZ2h0OmJlZm9y
ZXtyaWdodDoxMnB4O2xlZnQ6YXV0b30ubmF2YmFyIC5wdWxsLXJpZ2h0PmxpPi5kcm9wZG93bi1tZW51
OmFmdGVyLC5uYXZiYXIgLm5hdj5saT4uZHJvcGRvd24tbWVudS5wdWxsLXJpZ2h0OmFmdGVye3JpZ2h0
OjEzcHg7bGVmdDphdXRvfS5uYXZiYXIgLnB1bGwtcmlnaHQ+bGk+LmRyb3Bkb3duLW1lbnUgLmRyb3Bk
b3duLW1lbnUsLm5hdmJhciAubmF2PmxpPi5kcm9wZG93bi1tZW51LnB1bGwtcmlnaHQgLmRyb3Bkb3du
LW1lbnV7cmlnaHQ6MTAwJTtsZWZ0OmF1dG87bWFyZ2luLXJpZ2h0Oi0xcHg7bWFyZ2luLWxlZnQ6MDst
d2Via2l0LWJvcmRlci1yYWRpdXM6NnB4IDAgNnB4IDZweDstbW96LWJvcmRlci1yYWRpdXM6NnB4IDAg
NnB4IDZweDtib3JkZXItcmFkaXVzOjZweCAwIDZweCA2cHh9Lm5hdmJhci1pbnZlcnNlIC5uYXZiYXIt
aW5uZXJ7YmFja2dyb3VuZC1jb2xvcjojMWIxYjFiO2JhY2tncm91bmQtaW1hZ2U6LW1vei1saW5lYXIt
Z3JhZGllbnQodG9wLCMyMjIsIzExMSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWdyYWRpZW50KGxp
bmVhciwwIDAsMCAxMDAlLGZyb20oIzIyMiksdG8oIzExMSkpO2JhY2tncm91bmQtaW1hZ2U6LXdlYmtp
dC1saW5lYXItZ3JhZGllbnQodG9wLCMyMjIsIzExMSk7YmFja2dyb3VuZC1pbWFnZTotby1saW5lYXIt
Z3JhZGllbnQodG9wLCMyMjIsIzExMSk7YmFja2dyb3VuZC1pbWFnZTpsaW5lYXItZ3JhZGllbnQodG8g
Ym90dG9tLCMyMjIsIzExMSk7YmFja2dyb3VuZC1yZXBlYXQ6cmVwZWF0LXg7Ym9yZGVyLWNvbG9yOiMy
NTI1MjU7ZmlsdGVyOnByb2dpZDpEWEltYWdlVHJhbnNmb3JtLk1pY3Jvc29mdC5ncmFkaWVudChzdGFy
dENvbG9yc3RyPScjZmYyMjIyMjInLGVuZENvbG9yc3RyPScjZmYxMTExMTEnLEdyYWRpZW50VHlwZT0w
KX0ubmF2YmFyLWludmVyc2UgLmJyYW5kLC5uYXZiYXItaW52ZXJzZSAubmF2PmxpPmF7Y29sb3I6Izk5
OTt0ZXh0LXNoYWRvdzowIC0xcHggMCByZ2JhKDAsMCwwLDAuMjUpfS5uYXZiYXItaW52ZXJzZSAuYnJh
bmQ6aG92ZXIsLm5hdmJhci1pbnZlcnNlIC5uYXY+bGk+YTpob3ZlciwubmF2YmFyLWludmVyc2UgLmJy
YW5kOmZvY3VzLC5uYXZiYXItaW52ZXJzZSAubmF2PmxpPmE6Zm9jdXN7Y29sb3I6I2ZmZn0ubmF2YmFy
LWludmVyc2UgLmJyYW5ke2NvbG9yOiM5OTl9Lm5hdmJhci1pbnZlcnNlIC5uYXZiYXItdGV4dHtjb2xv
cjojOTk5fS5uYXZiYXItaW52ZXJzZSAubmF2PmxpPmE6Zm9jdXMsLm5hdmJhci1pbnZlcnNlIC5uYXY+
bGk+YTpob3Zlcntjb2xvcjojZmZmO2JhY2tncm91bmQtY29sb3I6dHJhbnNwYXJlbnR9Lm5hdmJhci1p
bnZlcnNlIC5uYXYgLmFjdGl2ZT5hLC5uYXZiYXItaW52ZXJzZSAubmF2IC5hY3RpdmU+YTpob3Zlciwu
bmF2YmFyLWludmVyc2UgLm5hdiAuYWN0aXZlPmE6Zm9jdXN7Y29sb3I6I2ZmZjtiYWNrZ3JvdW5kLWNv
bG9yOiMxMTF9Lm5hdmJhci1pbnZlcnNlIC5uYXZiYXItbGlua3tjb2xvcjojOTk5fS5uYXZiYXItaW52
ZXJzZSAubmF2YmFyLWxpbms6aG92ZXIsLm5hdmJhci1pbnZlcnNlIC5uYXZiYXItbGluazpmb2N1c3tj
b2xvcjojZmZmfS5uYXZiYXItaW52ZXJzZSAuZGl2aWRlci12ZXJ0aWNhbHtib3JkZXItcmlnaHQtY29s
b3I6IzIyMjtib3JkZXItbGVmdC1jb2xvcjojMTExfS5uYXZiYXItaW52ZXJzZSAubmF2IGxpLmRyb3Bk
b3duLm9wZW4+LmRyb3Bkb3duLXRvZ2dsZSwubmF2YmFyLWludmVyc2UgLm5hdiBsaS5kcm9wZG93bi5h
Y3RpdmU+LmRyb3Bkb3duLXRvZ2dsZSwubmF2YmFyLWludmVyc2UgLm5hdiBsaS5kcm9wZG93bi5vcGVu
LmFjdGl2ZT4uZHJvcGRvd24tdG9nZ2xle2NvbG9yOiNmZmY7YmFja2dyb3VuZC1jb2xvcjojMTExfS5u
YXZiYXItaW52ZXJzZSAubmF2IGxpLmRyb3Bkb3duPmE6aG92ZXIgLmNhcmV0LC5uYXZiYXItaW52ZXJz
ZSAubmF2IGxpLmRyb3Bkb3duPmE6Zm9jdXMgLmNhcmV0e2JvcmRlci10b3AtY29sb3I6I2ZmZjtib3Jk
ZXItYm90dG9tLWNvbG9yOiNmZmZ9Lm5hdmJhci1pbnZlcnNlIC5uYXYgbGkuZHJvcGRvd24+LmRyb3Bk
b3duLXRvZ2dsZSAuY2FyZXR7Ym9yZGVyLXRvcC1jb2xvcjojOTk5O2JvcmRlci1ib3R0b20tY29sb3I6
Izk5OX0ubmF2YmFyLWludmVyc2UgLm5hdiBsaS5kcm9wZG93bi5vcGVuPi5kcm9wZG93bi10b2dnbGUg
LmNhcmV0LC5uYXZiYXItaW52ZXJzZSAubmF2IGxpLmRyb3Bkb3duLmFjdGl2ZT4uZHJvcGRvd24tdG9n
Z2xlIC5jYXJldCwubmF2YmFyLWludmVyc2UgLm5hdiBsaS5kcm9wZG93bi5vcGVuLmFjdGl2ZT4uZHJv
cGRvd24tdG9nZ2xlIC5jYXJldHtib3JkZXItdG9wLWNvbG9yOiNmZmY7Ym9yZGVyLWJvdHRvbS1jb2xv
cjojZmZmfS5uYXZiYXItaW52ZXJzZSAubmF2YmFyLXNlYXJjaCAuc2VhcmNoLXF1ZXJ5e2NvbG9yOiNm
ZmY7YmFja2dyb3VuZC1jb2xvcjojNTE1MTUxO2JvcmRlci1jb2xvcjojMTExOy13ZWJraXQtYm94LXNo
YWRvdzppbnNldCAwIDFweCAycHggcmdiYSgwLDAsMCwwLjEpLDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1
NSwwLjE1KTstbW96LWJveC1zaGFkb3c6aW5zZXQgMCAxcHggMnB4IHJnYmEoMCwwLDAsMC4xKSwwIDFw
eCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4xNSk7Ym94LXNoYWRvdzppbnNldCAwIDFweCAycHggcmdiYSgw
LDAsMCwwLjEpLDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjE1KTstd2Via2l0LXRyYW5zaXRpb246
bm9uZTstbW96LXRyYW5zaXRpb246bm9uZTstby10cmFuc2l0aW9uOm5vbmU7dHJhbnNpdGlvbjpub25l
fS5uYXZiYXItaW52ZXJzZSAubmF2YmFyLXNlYXJjaCAuc2VhcmNoLXF1ZXJ5Oi1tb3otcGxhY2Vob2xk
ZXJ7Y29sb3I6I2NjY30ubmF2YmFyLWludmVyc2UgLm5hdmJhci1zZWFyY2ggLnNlYXJjaC1xdWVyeTot
bXMtaW5wdXQtcGxhY2Vob2xkZXJ7Y29sb3I6I2NjY30ubmF2YmFyLWludmVyc2UgLm5hdmJhci1zZWFy
Y2ggLnNlYXJjaC1xdWVyeTo6LXdlYmtpdC1pbnB1dC1wbGFjZWhvbGRlcntjb2xvcjojY2NjfS5uYXZi
YXItaW52ZXJzZSAubmF2YmFyLXNlYXJjaCAuc2VhcmNoLXF1ZXJ5OmZvY3VzLC5uYXZiYXItaW52ZXJz
ZSAubmF2YmFyLXNlYXJjaCAuc2VhcmNoLXF1ZXJ5LmZvY3VzZWR7cGFkZGluZzo1cHggMTVweDtjb2xv
cjojMzMzO3RleHQtc2hhZG93OjAgMXB4IDAgI2ZmZjtiYWNrZ3JvdW5kLWNvbG9yOiNmZmY7Ym9yZGVy
OjA7b3V0bGluZTowOy13ZWJraXQtYm94LXNoYWRvdzowIDAgM3B4IHJnYmEoMCwwLDAsMC4xNSk7LW1v
ei1ib3gtc2hhZG93OjAgMCAzcHggcmdiYSgwLDAsMCwwLjE1KTtib3gtc2hhZG93OjAgMCAzcHggcmdi
YSgwLDAsMCwwLjE1KX0ubmF2YmFyLWludmVyc2UgLmJ0bi1uYXZiYXJ7Y29sb3I6I2ZmZjt0ZXh0LXNo
YWRvdzowIC0xcHggMCByZ2JhKDAsMCwwLDAuMjUpO2JhY2tncm91bmQtY29sb3I6IzBlMGUwZTsqYmFj
a2dyb3VuZC1jb2xvcjojMDQwNDA0O2JhY2tncm91bmQtaW1hZ2U6LW1vei1saW5lYXItZ3JhZGllbnQo
dG9wLCMxNTE1MTUsIzA0MDQwNCk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWdyYWRpZW50KGxpbmVh
ciwwIDAsMCAxMDAlLGZyb20oIzE1MTUxNSksdG8oIzA0MDQwNCkpO2JhY2tncm91bmQtaW1hZ2U6LXdl
YmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCMxNTE1MTUsIzA0MDQwNCk7YmFja2dyb3VuZC1pbWFnZTot
by1saW5lYXItZ3JhZGllbnQodG9wLCMxNTE1MTUsIzA0MDQwNCk7YmFja2dyb3VuZC1pbWFnZTpsaW5l
YXItZ3JhZGllbnQodG8gYm90dG9tLCMxNTE1MTUsIzA0MDQwNCk7YmFja2dyb3VuZC1yZXBlYXQ6cmVw
ZWF0LXg7Ym9yZGVyLWNvbG9yOiMwNDA0MDQgIzA0MDQwNCAjMDAwO2JvcmRlci1jb2xvcjpyZ2JhKDAs
MCwwLDAuMSkgcmdiYSgwLDAsMCwwLjEpIHJnYmEoMCwwLDAsMC4yNSk7ZmlsdGVyOnByb2dpZDpEWElt
YWdlVHJhbnNmb3JtLk1pY3Jvc29mdC5ncmFkaWVudChzdGFydENvbG9yc3RyPScjZmYxNTE1MTUnLGVu
ZENvbG9yc3RyPScjZmYwNDA0MDQnLEdyYWRpZW50VHlwZT0wKTtmaWx0ZXI6cHJvZ2lkOkRYSW1hZ2VU
cmFuc2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KGVuYWJsZWQ9ZmFsc2UpfS5uYXZiYXItaW52ZXJzZSAu
YnRuLW5hdmJhcjpob3ZlciwubmF2YmFyLWludmVyc2UgLmJ0bi1uYXZiYXI6Zm9jdXMsLm5hdmJhci1p
bnZlcnNlIC5idG4tbmF2YmFyOmFjdGl2ZSwubmF2YmFyLWludmVyc2UgLmJ0bi1uYXZiYXIuYWN0aXZl
LC5uYXZiYXItaW52ZXJzZSAuYnRuLW5hdmJhci5kaXNhYmxlZCwubmF2YmFyLWludmVyc2UgLmJ0bi1u
YXZiYXJbZGlzYWJsZWRde2NvbG9yOiNmZmY7YmFja2dyb3VuZC1jb2xvcjojMDQwNDA0OypiYWNrZ3Jv
dW5kLWNvbG9yOiMwMDB9Lm5hdmJhci1pbnZlcnNlIC5idG4tbmF2YmFyOmFjdGl2ZSwubmF2YmFyLWlu
dmVyc2UgLmJ0bi1uYXZiYXIuYWN0aXZle2JhY2tncm91bmQtY29sb3I6IzAwMCBcOX0uYnJlYWRjcnVt
YntwYWRkaW5nOjhweCAxNXB4O21hcmdpbjowIDAgMjBweDtsaXN0LXN0eWxlOm5vbmU7YmFja2dyb3Vu
ZC1jb2xvcjojZjVmNWY1Oy13ZWJraXQtYm9yZGVyLXJhZGl1czo0cHg7LW1vei1ib3JkZXItcmFkaXVz
OjRweDtib3JkZXItcmFkaXVzOjRweH0uYnJlYWRjcnVtYj5saXtkaXNwbGF5OmlubGluZS1ibG9jazsq
ZGlzcGxheTppbmxpbmU7dGV4dC1zaGFkb3c6MCAxcHggMCAjZmZmOyp6b29tOjF9LmJyZWFkY3J1bWI+
bGk+LmRpdmlkZXJ7cGFkZGluZzowIDVweDtjb2xvcjojY2NjfS5icmVhZGNydW1iPi5hY3RpdmV7Y29s
b3I6Izk5OX0ucGFnaW5hdGlvbnttYXJnaW46MjBweCAwfS5wYWdpbmF0aW9uIHVse2Rpc3BsYXk6aW5s
aW5lLWJsb2NrOypkaXNwbGF5OmlubGluZTttYXJnaW4tYm90dG9tOjA7bWFyZ2luLWxlZnQ6MDstd2Vi
a2l0LWJvcmRlci1yYWRpdXM6NHB4Oy1tb3otYm9yZGVyLXJhZGl1czo0cHg7Ym9yZGVyLXJhZGl1czo0
cHg7Knpvb206MTstd2Via2l0LWJveC1zaGFkb3c6MCAxcHggMnB4IHJnYmEoMCwwLDAsMC4wNSk7LW1v
ei1ib3gtc2hhZG93OjAgMXB4IDJweCByZ2JhKDAsMCwwLDAuMDUpO2JveC1zaGFkb3c6MCAxcHggMnB4
IHJnYmEoMCwwLDAsMC4wNSl9LnBhZ2luYXRpb24gdWw+bGl7ZGlzcGxheTppbmxpbmV9LnBhZ2luYXRp
b24gdWw+bGk+YSwucGFnaW5hdGlvbiB1bD5saT5zcGFue2Zsb2F0OmxlZnQ7cGFkZGluZzo0cHggMTJw
eDtsaW5lLWhlaWdodDoyMHB4O3RleHQtZGVjb3JhdGlvbjpub25lO2JhY2tncm91bmQtY29sb3I6I2Zm
Zjtib3JkZXI6MXB4IHNvbGlkICNkZGQ7Ym9yZGVyLWxlZnQtd2lkdGg6MH0ucGFnaW5hdGlvbiB1bD5s
aT5hOmhvdmVyLC5wYWdpbmF0aW9uIHVsPmxpPmE6Zm9jdXMsLnBhZ2luYXRpb24gdWw+LmFjdGl2ZT5h
LC5wYWdpbmF0aW9uIHVsPi5hY3RpdmU+c3BhbntiYWNrZ3JvdW5kLWNvbG9yOiNmNWY1ZjV9LnBhZ2lu
YXRpb24gdWw+LmFjdGl2ZT5hLC5wYWdpbmF0aW9uIHVsPi5hY3RpdmU+c3Bhbntjb2xvcjojOTk5O2N1
cnNvcjpkZWZhdWx0fS5wYWdpbmF0aW9uIHVsPi5kaXNhYmxlZD5zcGFuLC5wYWdpbmF0aW9uIHVsPi5k
aXNhYmxlZD5hLC5wYWdpbmF0aW9uIHVsPi5kaXNhYmxlZD5hOmhvdmVyLC5wYWdpbmF0aW9uIHVsPi5k
aXNhYmxlZD5hOmZvY3Vze2NvbG9yOiM5OTk7Y3Vyc29yOmRlZmF1bHQ7YmFja2dyb3VuZC1jb2xvcjp0
cmFuc3BhcmVudH0ucGFnaW5hdGlvbiB1bD5saTpmaXJzdC1jaGlsZD5hLC5wYWdpbmF0aW9uIHVsPmxp
OmZpcnN0LWNoaWxkPnNwYW57Ym9yZGVyLWxlZnQtd2lkdGg6MXB4Oy13ZWJraXQtYm9yZGVyLWJvdHRv
bS1sZWZ0LXJhZGl1czo0cHg7Ym9yZGVyLWJvdHRvbS1sZWZ0LXJhZGl1czo0cHg7LXdlYmtpdC1ib3Jk
ZXItdG9wLWxlZnQtcmFkaXVzOjRweDtib3JkZXItdG9wLWxlZnQtcmFkaXVzOjRweDstbW96LWJvcmRl
ci1yYWRpdXMtYm90dG9tbGVmdDo0cHg7LW1vei1ib3JkZXItcmFkaXVzLXRvcGxlZnQ6NHB4fS5wYWdp
bmF0aW9uIHVsPmxpOmxhc3QtY2hpbGQ+YSwucGFnaW5hdGlvbiB1bD5saTpsYXN0LWNoaWxkPnNwYW57
LXdlYmtpdC1ib3JkZXItdG9wLXJpZ2h0LXJhZGl1czo0cHg7Ym9yZGVyLXRvcC1yaWdodC1yYWRpdXM6
NHB4Oy13ZWJraXQtYm9yZGVyLWJvdHRvbS1yaWdodC1yYWRpdXM6NHB4O2JvcmRlci1ib3R0b20tcmln
aHQtcmFkaXVzOjRweDstbW96LWJvcmRlci1yYWRpdXMtdG9wcmlnaHQ6NHB4Oy1tb3otYm9yZGVyLXJh
ZGl1cy1ib3R0b21yaWdodDo0cHh9LnBhZ2luYXRpb24tY2VudGVyZWR7dGV4dC1hbGlnbjpjZW50ZXJ9
LnBhZ2luYXRpb24tcmlnaHR7dGV4dC1hbGlnbjpyaWdodH0ucGFnaW5hdGlvbi1sYXJnZSB1bD5saT5h
LC5wYWdpbmF0aW9uLWxhcmdlIHVsPmxpPnNwYW57cGFkZGluZzoxMXB4IDE5cHg7Zm9udC1zaXplOjE3
LjVweH0ucGFnaW5hdGlvbi1sYXJnZSB1bD5saTpmaXJzdC1jaGlsZD5hLC5wYWdpbmF0aW9uLWxhcmdl
IHVsPmxpOmZpcnN0LWNoaWxkPnNwYW57LXdlYmtpdC1ib3JkZXItYm90dG9tLWxlZnQtcmFkaXVzOjZw
eDtib3JkZXItYm90dG9tLWxlZnQtcmFkaXVzOjZweDstd2Via2l0LWJvcmRlci10b3AtbGVmdC1yYWRp
dXM6NnB4O2JvcmRlci10b3AtbGVmdC1yYWRpdXM6NnB4Oy1tb3otYm9yZGVyLXJhZGl1cy1ib3R0b21s
ZWZ0OjZweDstbW96LWJvcmRlci1yYWRpdXMtdG9wbGVmdDo2cHh9LnBhZ2luYXRpb24tbGFyZ2UgdWw+
bGk6bGFzdC1jaGlsZD5hLC5wYWdpbmF0aW9uLWxhcmdlIHVsPmxpOmxhc3QtY2hpbGQ+c3Bhbnstd2Vi
a2l0LWJvcmRlci10b3AtcmlnaHQtcmFkaXVzOjZweDtib3JkZXItdG9wLXJpZ2h0LXJhZGl1czo2cHg7
LXdlYmtpdC1ib3JkZXItYm90dG9tLXJpZ2h0LXJhZGl1czo2cHg7Ym9yZGVyLWJvdHRvbS1yaWdodC1y
YWRpdXM6NnB4Oy1tb3otYm9yZGVyLXJhZGl1cy10b3ByaWdodDo2cHg7LW1vei1ib3JkZXItcmFkaXVz
LWJvdHRvbXJpZ2h0OjZweH0ucGFnaW5hdGlvbi1taW5pIHVsPmxpOmZpcnN0LWNoaWxkPmEsLnBhZ2lu
YXRpb24tc21hbGwgdWw+bGk6Zmlyc3QtY2hpbGQ+YSwucGFnaW5hdGlvbi1taW5pIHVsPmxpOmZpcnN0
LWNoaWxkPnNwYW4sLnBhZ2luYXRpb24tc21hbGwgdWw+bGk6Zmlyc3QtY2hpbGQ+c3Bhbnstd2Via2l0
LWJvcmRlci1ib3R0b20tbGVmdC1yYWRpdXM6M3B4O2JvcmRlci1ib3R0b20tbGVmdC1yYWRpdXM6M3B4
Oy13ZWJraXQtYm9yZGVyLXRvcC1sZWZ0LXJhZGl1czozcHg7Ym9yZGVyLXRvcC1sZWZ0LXJhZGl1czoz
cHg7LW1vei1ib3JkZXItcmFkaXVzLWJvdHRvbWxlZnQ6M3B4Oy1tb3otYm9yZGVyLXJhZGl1cy10b3Bs
ZWZ0OjNweH0ucGFnaW5hdGlvbi1taW5pIHVsPmxpOmxhc3QtY2hpbGQ+YSwucGFnaW5hdGlvbi1zbWFs
bCB1bD5saTpsYXN0LWNoaWxkPmEsLnBhZ2luYXRpb24tbWluaSB1bD5saTpsYXN0LWNoaWxkPnNwYW4s
LnBhZ2luYXRpb24tc21hbGwgdWw+bGk6bGFzdC1jaGlsZD5zcGFuey13ZWJraXQtYm9yZGVyLXRvcC1y
aWdodC1yYWRpdXM6M3B4O2JvcmRlci10b3AtcmlnaHQtcmFkaXVzOjNweDstd2Via2l0LWJvcmRlci1i
b3R0b20tcmlnaHQtcmFkaXVzOjNweDtib3JkZXItYm90dG9tLXJpZ2h0LXJhZGl1czozcHg7LW1vei1i
b3JkZXItcmFkaXVzLXRvcHJpZ2h0OjNweDstbW96LWJvcmRlci1yYWRpdXMtYm90dG9tcmlnaHQ6M3B4
fS5wYWdpbmF0aW9uLXNtYWxsIHVsPmxpPmEsLnBhZ2luYXRpb24tc21hbGwgdWw+bGk+c3BhbntwYWRk
aW5nOjJweCAxMHB4O2ZvbnQtc2l6ZToxMS45cHh9LnBhZ2luYXRpb24tbWluaSB1bD5saT5hLC5wYWdp
bmF0aW9uLW1pbmkgdWw+bGk+c3BhbntwYWRkaW5nOjAgNnB4O2ZvbnQtc2l6ZToxMC41cHh9LnBhZ2Vy
e21hcmdpbjoyMHB4IDA7dGV4dC1hbGlnbjpjZW50ZXI7bGlzdC1zdHlsZTpub25lOyp6b29tOjF9LnBh
Z2VyOmJlZm9yZSwucGFnZXI6YWZ0ZXJ7ZGlzcGxheTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6
IiJ9LnBhZ2VyOmFmdGVye2NsZWFyOmJvdGh9LnBhZ2VyIGxpe2Rpc3BsYXk6aW5saW5lfS5wYWdlciBs
aT5hLC5wYWdlciBsaT5zcGFue2Rpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6NXB4IDE0cHg7YmFj
a2dyb3VuZC1jb2xvcjojZmZmO2JvcmRlcjoxcHggc29saWQgI2RkZDstd2Via2l0LWJvcmRlci1yYWRp
dXM6MTVweDstbW96LWJvcmRlci1yYWRpdXM6MTVweDtib3JkZXItcmFkaXVzOjE1cHh9LnBhZ2VyIGxp
PmE6aG92ZXIsLnBhZ2VyIGxpPmE6Zm9jdXN7dGV4dC1kZWNvcmF0aW9uOm5vbmU7YmFja2dyb3VuZC1j
b2xvcjojZjVmNWY1fS5wYWdlciAubmV4dD5hLC5wYWdlciAubmV4dD5zcGFue2Zsb2F0OnJpZ2h0fS5w
YWdlciAucHJldmlvdXM+YSwucGFnZXIgLnByZXZpb3VzPnNwYW57ZmxvYXQ6bGVmdH0ucGFnZXIgLmRp
c2FibGVkPmEsLnBhZ2VyIC5kaXNhYmxlZD5hOmhvdmVyLC5wYWdlciAuZGlzYWJsZWQ+YTpmb2N1cywu
cGFnZXIgLmRpc2FibGVkPnNwYW57Y29sb3I6Izk5OTtjdXJzb3I6ZGVmYXVsdDtiYWNrZ3JvdW5kLWNv
bG9yOiNmZmZ9Lm1vZGFsLWJhY2tkcm9we3Bvc2l0aW9uOmZpeGVkO3RvcDowO3JpZ2h0OjA7Ym90dG9t
OjA7bGVmdDowO3otaW5kZXg6MTA0MDtiYWNrZ3JvdW5kLWNvbG9yOiMwMDB9Lm1vZGFsLWJhY2tkcm9w
LmZhZGV7b3BhY2l0eTowfS5tb2RhbC1iYWNrZHJvcCwubW9kYWwtYmFja2Ryb3AuZmFkZS5pbntvcGFj
aXR5Oi44O2ZpbHRlcjphbHBoYShvcGFjaXR5PTgwKX0ubW9kYWx7cG9zaXRpb246Zml4ZWQ7dG9wOjEw
JTtsZWZ0OjUwJTt6LWluZGV4OjEwNTA7d2lkdGg6NTYwcHg7bWFyZ2luLWxlZnQ6LTI4MHB4O2JhY2tn
cm91bmQtY29sb3I6I2ZmZjtib3JkZXI6MXB4IHNvbGlkICM5OTk7Ym9yZGVyOjFweCBzb2xpZCByZ2Jh
KDAsMCwwLDAuMyk7KmJvcmRlcjoxcHggc29saWQgIzk5OTstd2Via2l0LWJvcmRlci1yYWRpdXM6NnB4
Oy1tb3otYm9yZGVyLXJhZGl1czo2cHg7Ym9yZGVyLXJhZGl1czo2cHg7b3V0bGluZTowOy13ZWJraXQt
Ym94LXNoYWRvdzowIDNweCA3cHggcmdiYSgwLDAsMCwwLjMpOy1tb3otYm94LXNoYWRvdzowIDNweCA3
cHggcmdiYSgwLDAsMCwwLjMpO2JveC1zaGFkb3c6MCAzcHggN3B4IHJnYmEoMCwwLDAsMC4zKTstd2Vi
a2l0LWJhY2tncm91bmQtY2xpcDpwYWRkaW5nLWJveDstbW96LWJhY2tncm91bmQtY2xpcDpwYWRkaW5n
LWJveDtiYWNrZ3JvdW5kLWNsaXA6cGFkZGluZy1ib3h9Lm1vZGFsLmZhZGV7dG9wOi0yNSU7LXdlYmtp
dC10cmFuc2l0aW9uOm9wYWNpdHkgLjNzIGxpbmVhcix0b3AgLjNzIGVhc2Utb3V0Oy1tb3otdHJhbnNp
dGlvbjpvcGFjaXR5IC4zcyBsaW5lYXIsdG9wIC4zcyBlYXNlLW91dDstby10cmFuc2l0aW9uOm9wYWNp
dHkgLjNzIGxpbmVhcix0b3AgLjNzIGVhc2Utb3V0O3RyYW5zaXRpb246b3BhY2l0eSAuM3MgbGluZWFy
LHRvcCAuM3MgZWFzZS1vdXR9Lm1vZGFsLmZhZGUuaW57dG9wOjEwJX0ubW9kYWwtaGVhZGVye3BhZGRp
bmc6OXB4IDE1cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgI2VlZX0ubW9kYWwtaGVhZGVyIC5jbG9z
ZXttYXJnaW4tdG9wOjJweH0ubW9kYWwtaGVhZGVyIGgze21hcmdpbjowO2xpbmUtaGVpZ2h0OjMwcHh9
Lm1vZGFsLWJvZHl7cG9zaXRpb246cmVsYXRpdmU7bWF4LWhlaWdodDo0MDBweDtwYWRkaW5nOjE1cHg7
b3ZlcmZsb3cteTphdXRvfS5tb2RhbC1mb3Jte21hcmdpbi1ib3R0b206MH0ubW9kYWwtZm9vdGVye3Bh
ZGRpbmc6MTRweCAxNXB4IDE1cHg7bWFyZ2luLWJvdHRvbTowO3RleHQtYWxpZ246cmlnaHQ7YmFja2dy
b3VuZC1jb2xvcjojZjVmNWY1O2JvcmRlci10b3A6MXB4IHNvbGlkICNkZGQ7LXdlYmtpdC1ib3JkZXIt
cmFkaXVzOjAgMCA2cHggNnB4Oy1tb3otYm9yZGVyLXJhZGl1czowIDAgNnB4IDZweDtib3JkZXItcmFk
aXVzOjAgMCA2cHggNnB4Oyp6b29tOjE7LXdlYmtpdC1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDAgI2Zm
ZjstbW96LWJveC1zaGFkb3c6aW5zZXQgMCAxcHggMCAjZmZmO2JveC1zaGFkb3c6aW5zZXQgMCAxcHgg
MCAjZmZmfS5tb2RhbC1mb290ZXI6YmVmb3JlLC5tb2RhbC1mb290ZXI6YWZ0ZXJ7ZGlzcGxheTp0YWJs
ZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9Lm1vZGFsLWZvb3RlcjphZnRlcntjbGVhcjpib3RofS5t
b2RhbC1mb290ZXIgLmJ0bisuYnRue21hcmdpbi1ib3R0b206MDttYXJnaW4tbGVmdDo1cHh9Lm1vZGFs
LWZvb3RlciAuYnRuLWdyb3VwIC5idG4rLmJ0bnttYXJnaW4tbGVmdDotMXB4fS5tb2RhbC1mb290ZXIg
LmJ0bi1ibG9jaysuYnRuLWJsb2Nre21hcmdpbi1sZWZ0OjB9LnRvb2x0aXB7cG9zaXRpb246YWJzb2x1
dGU7ei1pbmRleDoxMDMwO2Rpc3BsYXk6YmxvY2s7Zm9udC1zaXplOjExcHg7bGluZS1oZWlnaHQ6MS40
O29wYWNpdHk6MDtmaWx0ZXI6YWxwaGEob3BhY2l0eT0wKTt2aXNpYmlsaXR5OnZpc2libGV9LnRvb2x0
aXAuaW57b3BhY2l0eTouODtmaWx0ZXI6YWxwaGEob3BhY2l0eT04MCl9LnRvb2x0aXAudG9we3BhZGRp
bmc6NXB4IDA7bWFyZ2luLXRvcDotM3B4fS50b29sdGlwLnJpZ2h0e3BhZGRpbmc6MCA1cHg7bWFyZ2lu
LWxlZnQ6M3B4fS50b29sdGlwLmJvdHRvbXtwYWRkaW5nOjVweCAwO21hcmdpbi10b3A6M3B4fS50b29s
dGlwLmxlZnR7cGFkZGluZzowIDVweDttYXJnaW4tbGVmdDotM3B4fS50b29sdGlwLWlubmVye21heC13
aWR0aDoyMDBweDtwYWRkaW5nOjhweDtjb2xvcjojZmZmO3RleHQtYWxpZ246Y2VudGVyO3RleHQtZGVj
b3JhdGlvbjpub25lO2JhY2tncm91bmQtY29sb3I6IzAwMDstd2Via2l0LWJvcmRlci1yYWRpdXM6NHB4
Oy1tb3otYm9yZGVyLXJhZGl1czo0cHg7Ym9yZGVyLXJhZGl1czo0cHh9LnRvb2x0aXAtYXJyb3d7cG9z
aXRpb246YWJzb2x1dGU7d2lkdGg6MDtoZWlnaHQ6MDtib3JkZXItY29sb3I6dHJhbnNwYXJlbnQ7Ym9y
ZGVyLXN0eWxlOnNvbGlkfS50b29sdGlwLnRvcCAudG9vbHRpcC1hcnJvd3tib3R0b206MDtsZWZ0OjUw
JTttYXJnaW4tbGVmdDotNXB4O2JvcmRlci10b3AtY29sb3I6IzAwMDtib3JkZXItd2lkdGg6NXB4IDVw
eCAwfS50b29sdGlwLnJpZ2h0IC50b29sdGlwLWFycm93e3RvcDo1MCU7bGVmdDowO21hcmdpbi10b3A6
LTVweDtib3JkZXItcmlnaHQtY29sb3I6IzAwMDtib3JkZXItd2lkdGg6NXB4IDVweCA1cHggMH0udG9v
bHRpcC5sZWZ0IC50b29sdGlwLWFycm93e3RvcDo1MCU7cmlnaHQ6MDttYXJnaW4tdG9wOi01cHg7Ym9y
ZGVyLWxlZnQtY29sb3I6IzAwMDtib3JkZXItd2lkdGg6NXB4IDAgNXB4IDVweH0udG9vbHRpcC5ib3R0
b20gLnRvb2x0aXAtYXJyb3d7dG9wOjA7bGVmdDo1MCU7bWFyZ2luLWxlZnQ6LTVweDtib3JkZXItYm90
dG9tLWNvbG9yOiMwMDA7Ym9yZGVyLXdpZHRoOjAgNXB4IDVweH0ucG9wb3Zlcntwb3NpdGlvbjphYnNv
bHV0ZTt0b3A6MDtsZWZ0OjA7ei1pbmRleDoxMDEwO2Rpc3BsYXk6bm9uZTttYXgtd2lkdGg6Mjc2cHg7
cGFkZGluZzoxcHg7dGV4dC1hbGlnbjpsZWZ0O3doaXRlLXNwYWNlOm5vcm1hbDtiYWNrZ3JvdW5kLWNv
bG9yOiNmZmY7Ym9yZGVyOjFweCBzb2xpZCAjY2NjO2JvcmRlcjoxcHggc29saWQgcmdiYSgwLDAsMCww
LjIpOy13ZWJraXQtYm9yZGVyLXJhZGl1czo2cHg7LW1vei1ib3JkZXItcmFkaXVzOjZweDtib3JkZXIt
cmFkaXVzOjZweDstd2Via2l0LWJveC1zaGFkb3c6MCA1cHggMTBweCByZ2JhKDAsMCwwLDAuMik7LW1v
ei1ib3gtc2hhZG93OjAgNXB4IDEwcHggcmdiYSgwLDAsMCwwLjIpO2JveC1zaGFkb3c6MCA1cHggMTBw
eCByZ2JhKDAsMCwwLDAuMik7LXdlYmtpdC1iYWNrZ3JvdW5kLWNsaXA6cGFkZGluZy1ib3g7LW1vei1i
YWNrZ3JvdW5kLWNsaXA6cGFkZGluZztiYWNrZ3JvdW5kLWNsaXA6cGFkZGluZy1ib3h9LnBvcG92ZXIu
dG9we21hcmdpbi10b3A6LTEwcHh9LnBvcG92ZXIucmlnaHR7bWFyZ2luLWxlZnQ6MTBweH0ucG9wb3Zl
ci5ib3R0b217bWFyZ2luLXRvcDoxMHB4fS5wb3BvdmVyLmxlZnR7bWFyZ2luLWxlZnQ6LTEwcHh9LnBv
cG92ZXItdGl0bGV7cGFkZGluZzo4cHggMTRweDttYXJnaW46MDtmb250LXNpemU6MTRweDtmb250LXdl
aWdodDpub3JtYWw7bGluZS1oZWlnaHQ6MThweDtiYWNrZ3JvdW5kLWNvbG9yOiNmN2Y3Zjc7Ym9yZGVy
LWJvdHRvbToxcHggc29saWQgI2ViZWJlYjstd2Via2l0LWJvcmRlci1yYWRpdXM6NXB4IDVweCAwIDA7
LW1vei1ib3JkZXItcmFkaXVzOjVweCA1cHggMCAwO2JvcmRlci1yYWRpdXM6NXB4IDVweCAwIDB9LnBv
cG92ZXItdGl0bGU6ZW1wdHl7ZGlzcGxheTpub25lfS5wb3BvdmVyLWNvbnRlbnR7cGFkZGluZzo5cHgg
MTRweH0ucG9wb3ZlciAuYXJyb3csLnBvcG92ZXIgLmFycm93OmFmdGVye3Bvc2l0aW9uOmFic29sdXRl
O2Rpc3BsYXk6YmxvY2s7d2lkdGg6MDtoZWlnaHQ6MDtib3JkZXItY29sb3I6dHJhbnNwYXJlbnQ7Ym9y
ZGVyLXN0eWxlOnNvbGlkfS5wb3BvdmVyIC5hcnJvd3tib3JkZXItd2lkdGg6MTFweH0ucG9wb3ZlciAu
YXJyb3c6YWZ0ZXJ7Ym9yZGVyLXdpZHRoOjEwcHg7Y29udGVudDoiIn0ucG9wb3Zlci50b3AgLmFycm93
e2JvdHRvbTotMTFweDtsZWZ0OjUwJTttYXJnaW4tbGVmdDotMTFweDtib3JkZXItdG9wLWNvbG9yOiM5
OTk7Ym9yZGVyLXRvcC1jb2xvcjpyZ2JhKDAsMCwwLDAuMjUpO2JvcmRlci1ib3R0b20td2lkdGg6MH0u
cG9wb3Zlci50b3AgLmFycm93OmFmdGVye2JvdHRvbToxcHg7bWFyZ2luLWxlZnQ6LTEwcHg7Ym9yZGVy
LXRvcC1jb2xvcjojZmZmO2JvcmRlci1ib3R0b20td2lkdGg6MH0ucG9wb3Zlci5yaWdodCAuYXJyb3d7
dG9wOjUwJTtsZWZ0Oi0xMXB4O21hcmdpbi10b3A6LTExcHg7Ym9yZGVyLXJpZ2h0LWNvbG9yOiM5OTk7
Ym9yZGVyLXJpZ2h0LWNvbG9yOnJnYmEoMCwwLDAsMC4yNSk7Ym9yZGVyLWxlZnQtd2lkdGg6MH0ucG9w
b3Zlci5yaWdodCAuYXJyb3c6YWZ0ZXJ7Ym90dG9tOi0xMHB4O2xlZnQ6MXB4O2JvcmRlci1yaWdodC1j
b2xvcjojZmZmO2JvcmRlci1sZWZ0LXdpZHRoOjB9LnBvcG92ZXIuYm90dG9tIC5hcnJvd3t0b3A6LTEx
cHg7bGVmdDo1MCU7bWFyZ2luLWxlZnQ6LTExcHg7Ym9yZGVyLWJvdHRvbS1jb2xvcjojOTk5O2JvcmRl
ci1ib3R0b20tY29sb3I6cmdiYSgwLDAsMCwwLjI1KTtib3JkZXItdG9wLXdpZHRoOjB9LnBvcG92ZXIu
Ym90dG9tIC5hcnJvdzphZnRlcnt0b3A6MXB4O21hcmdpbi1sZWZ0Oi0xMHB4O2JvcmRlci1ib3R0b20t
Y29sb3I6I2ZmZjtib3JkZXItdG9wLXdpZHRoOjB9LnBvcG92ZXIubGVmdCAuYXJyb3d7dG9wOjUwJTty
aWdodDotMTFweDttYXJnaW4tdG9wOi0xMXB4O2JvcmRlci1sZWZ0LWNvbG9yOiM5OTk7Ym9yZGVyLWxl
ZnQtY29sb3I6cmdiYSgwLDAsMCwwLjI1KTtib3JkZXItcmlnaHQtd2lkdGg6MH0ucG9wb3Zlci5sZWZ0
IC5hcnJvdzphZnRlcntyaWdodDoxcHg7Ym90dG9tOi0xMHB4O2JvcmRlci1sZWZ0LWNvbG9yOiNmZmY7
Ym9yZGVyLXJpZ2h0LXdpZHRoOjB9LnRodW1ibmFpbHN7bWFyZ2luLWxlZnQ6LTIwcHg7bGlzdC1zdHls
ZTpub25lOyp6b29tOjF9LnRodW1ibmFpbHM6YmVmb3JlLC50aHVtYm5haWxzOmFmdGVye2Rpc3BsYXk6
dGFibGU7bGluZS1oZWlnaHQ6MDtjb250ZW50OiIifS50aHVtYm5haWxzOmFmdGVye2NsZWFyOmJvdGh9
LnJvdy1mbHVpZCAudGh1bWJuYWlsc3ttYXJnaW4tbGVmdDowfS50aHVtYm5haWxzPmxpe2Zsb2F0Omxl
ZnQ7bWFyZ2luLWJvdHRvbToyMHB4O21hcmdpbi1sZWZ0OjIwcHh9LnRodW1ibmFpbHtkaXNwbGF5OmJs
b2NrO3BhZGRpbmc6NHB4O2xpbmUtaGVpZ2h0OjIwcHg7Ym9yZGVyOjFweCBzb2xpZCAjZGRkOy13ZWJr
aXQtYm9yZGVyLXJhZGl1czo0cHg7LW1vei1ib3JkZXItcmFkaXVzOjRweDtib3JkZXItcmFkaXVzOjRw
eDstd2Via2l0LWJveC1zaGFkb3c6MCAxcHggM3B4IHJnYmEoMCwwLDAsMC4wNTUpOy1tb3otYm94LXNo
YWRvdzowIDFweCAzcHggcmdiYSgwLDAsMCwwLjA1NSk7Ym94LXNoYWRvdzowIDFweCAzcHggcmdiYSgw
LDAsMCwwLjA1NSk7LXdlYmtpdC10cmFuc2l0aW9uOmFsbCAuMnMgZWFzZS1pbi1vdXQ7LW1vei10cmFu
c2l0aW9uOmFsbCAuMnMgZWFzZS1pbi1vdXQ7LW8tdHJhbnNpdGlvbjphbGwgLjJzIGVhc2UtaW4tb3V0
O3RyYW5zaXRpb246YWxsIC4ycyBlYXNlLWluLW91dH1hLnRodW1ibmFpbDpob3ZlcixhLnRodW1ibmFp
bDpmb2N1c3tib3JkZXItY29sb3I6IzA4Yzstd2Via2l0LWJveC1zaGFkb3c6MCAxcHggNHB4IHJnYmEo
MCwxMDUsMjE0LDAuMjUpOy1tb3otYm94LXNoYWRvdzowIDFweCA0cHggcmdiYSgwLDEwNSwyMTQsMC4y
NSk7Ym94LXNoYWRvdzowIDFweCA0cHggcmdiYSgwLDEwNSwyMTQsMC4yNSl9LnRodW1ibmFpbD5pbWd7
ZGlzcGxheTpibG9jazttYXgtd2lkdGg6MTAwJTttYXJnaW4tcmlnaHQ6YXV0bzttYXJnaW4tbGVmdDph
dXRvfS50aHVtYm5haWwgLmNhcHRpb257cGFkZGluZzo5cHg7Y29sb3I6IzU1NX0ubWVkaWEsLm1lZGlh
LWJvZHl7b3ZlcmZsb3c6aGlkZGVuOypvdmVyZmxvdzp2aXNpYmxlO3pvb206MX0ubWVkaWEsLm1lZGlh
IC5tZWRpYXttYXJnaW4tdG9wOjE1cHh9Lm1lZGlhOmZpcnN0LWNoaWxke21hcmdpbi10b3A6MH0ubWVk
aWEtb2JqZWN0e2Rpc3BsYXk6YmxvY2t9Lm1lZGlhLWhlYWRpbmd7bWFyZ2luOjAgMCA1cHh9Lm1lZGlh
Pi5wdWxsLWxlZnR7bWFyZ2luLXJpZ2h0OjEwcHh9Lm1lZGlhPi5wdWxsLXJpZ2h0e21hcmdpbi1sZWZ0
OjEwcHh9Lm1lZGlhLWxpc3R7bWFyZ2luLWxlZnQ6MDtsaXN0LXN0eWxlOm5vbmV9LmxhYmVsLC5iYWRn
ZXtkaXNwbGF5OmlubGluZS1ibG9jaztwYWRkaW5nOjJweCA0cHg7Zm9udC1zaXplOjExLjg0NHB4O2Zv
bnQtd2VpZ2h0OmJvbGQ7bGluZS1oZWlnaHQ6MTRweDtjb2xvcjojZmZmO3RleHQtc2hhZG93OjAgLTFw
eCAwIHJnYmEoMCwwLDAsMC4yNSk7d2hpdGUtc3BhY2U6bm93cmFwO3ZlcnRpY2FsLWFsaWduOmJhc2Vs
aW5lO2JhY2tncm91bmQtY29sb3I6Izk5OX0ubGFiZWx7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjNweDst
bW96LWJvcmRlci1yYWRpdXM6M3B4O2JvcmRlci1yYWRpdXM6M3B4fS5iYWRnZXtwYWRkaW5nLXJpZ2h0
OjlweDtwYWRkaW5nLWxlZnQ6OXB4Oy13ZWJraXQtYm9yZGVyLXJhZGl1czo5cHg7LW1vei1ib3JkZXIt
cmFkaXVzOjlweDtib3JkZXItcmFkaXVzOjlweH0ubGFiZWw6ZW1wdHksLmJhZGdlOmVtcHR5e2Rpc3Bs
YXk6bm9uZX1hLmxhYmVsOmhvdmVyLGEubGFiZWw6Zm9jdXMsYS5iYWRnZTpob3ZlcixhLmJhZGdlOmZv
Y3Vze2NvbG9yOiNmZmY7dGV4dC1kZWNvcmF0aW9uOm5vbmU7Y3Vyc29yOnBvaW50ZXJ9LmxhYmVsLWlt
cG9ydGFudCwuYmFkZ2UtaW1wb3J0YW50e2JhY2tncm91bmQtY29sb3I6I2I5NGE0OH0ubGFiZWwtaW1w
b3J0YW50W2hyZWZdLC5iYWRnZS1pbXBvcnRhbnRbaHJlZl17YmFja2dyb3VuZC1jb2xvcjojOTUzYjM5
fS5sYWJlbC13YXJuaW5nLC5iYWRnZS13YXJuaW5ne2JhY2tncm91bmQtY29sb3I6I2Y4OTQwNn0ubGFi
ZWwtd2FybmluZ1tocmVmXSwuYmFkZ2Utd2FybmluZ1tocmVmXXtiYWNrZ3JvdW5kLWNvbG9yOiNjNjc2
MDV9LmxhYmVsLXN1Y2Nlc3MsLmJhZGdlLXN1Y2Nlc3N7YmFja2dyb3VuZC1jb2xvcjojNDY4ODQ3fS5s
YWJlbC1zdWNjZXNzW2hyZWZdLC5iYWRnZS1zdWNjZXNzW2hyZWZde2JhY2tncm91bmQtY29sb3I6IzM1
NjYzNX0ubGFiZWwtaW5mbywuYmFkZ2UtaW5mb3tiYWNrZ3JvdW5kLWNvbG9yOiMzYTg3YWR9LmxhYmVs
LWluZm9baHJlZl0sLmJhZGdlLWluZm9baHJlZl17YmFja2dyb3VuZC1jb2xvcjojMmQ2OTg3fS5sYWJl
bC1pbnZlcnNlLC5iYWRnZS1pbnZlcnNle2JhY2tncm91bmQtY29sb3I6IzMzM30ubGFiZWwtaW52ZXJz
ZVtocmVmXSwuYmFkZ2UtaW52ZXJzZVtocmVmXXtiYWNrZ3JvdW5kLWNvbG9yOiMxYTFhMWF9LmJ0biAu
bGFiZWwsLmJ0biAuYmFkZ2V7cG9zaXRpb246cmVsYXRpdmU7dG9wOi0xcHh9LmJ0bi1taW5pIC5sYWJl
bCwuYnRuLW1pbmkgLmJhZGdle3RvcDowfUAtd2Via2l0LWtleWZyYW1lcyBwcm9ncmVzcy1iYXItc3Ry
aXBlc3tmcm9te2JhY2tncm91bmQtcG9zaXRpb246NDBweCAwfXRve2JhY2tncm91bmQtcG9zaXRpb246
MCAwfX1ALW1vei1rZXlmcmFtZXMgcHJvZ3Jlc3MtYmFyLXN0cmlwZXN7ZnJvbXtiYWNrZ3JvdW5kLXBv
c2l0aW9uOjQwcHggMH10b3tiYWNrZ3JvdW5kLXBvc2l0aW9uOjAgMH19QC1tcy1rZXlmcmFtZXMgcHJv
Z3Jlc3MtYmFyLXN0cmlwZXN7ZnJvbXtiYWNrZ3JvdW5kLXBvc2l0aW9uOjQwcHggMH10b3tiYWNrZ3Jv
dW5kLXBvc2l0aW9uOjAgMH19QC1vLWtleWZyYW1lcyBwcm9ncmVzcy1iYXItc3RyaXBlc3tmcm9te2Jh
Y2tncm91bmQtcG9zaXRpb246MCAwfXRve2JhY2tncm91bmQtcG9zaXRpb246NDBweCAwfX1Aa2V5ZnJh
bWVzIHByb2dyZXNzLWJhci1zdHJpcGVze2Zyb217YmFja2dyb3VuZC1wb3NpdGlvbjo0MHB4IDB9dG97
YmFja2dyb3VuZC1wb3NpdGlvbjowIDB9fS5wcm9ncmVzc3toZWlnaHQ6MjBweDttYXJnaW4tYm90dG9t
OjIwcHg7b3ZlcmZsb3c6aGlkZGVuO2JhY2tncm91bmQtY29sb3I6I2Y3ZjdmNztiYWNrZ3JvdW5kLWlt
YWdlOi1tb3otbGluZWFyLWdyYWRpZW50KHRvcCwjZjVmNWY1LCNmOWY5ZjkpO2JhY2tncm91bmQtaW1h
Z2U6LXdlYmtpdC1ncmFkaWVudChsaW5lYXIsMCAwLDAgMTAwJSxmcm9tKCNmNWY1ZjUpLHRvKCNmOWY5
ZjkpKTtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwjZjVmNWY1LCNm
OWY5ZjkpO2JhY2tncm91bmQtaW1hZ2U6LW8tbGluZWFyLWdyYWRpZW50KHRvcCwjZjVmNWY1LCNmOWY5
ZjkpO2JhY2tncm91bmQtaW1hZ2U6bGluZWFyLWdyYWRpZW50KHRvIGJvdHRvbSwjZjVmNWY1LCNmOWY5
ZjkpO2JhY2tncm91bmQtcmVwZWF0OnJlcGVhdC14Oy13ZWJraXQtYm9yZGVyLXJhZGl1czo0cHg7LW1v
ei1ib3JkZXItcmFkaXVzOjRweDtib3JkZXItcmFkaXVzOjRweDtmaWx0ZXI6cHJvZ2lkOkRYSW1hZ2VU
cmFuc2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9JyNmZmY1ZjVmNScsZW5kQ29s
b3JzdHI9JyNmZmY5ZjlmOScsR3JhZGllbnRUeXBlPTApOy13ZWJraXQtYm94LXNoYWRvdzppbnNldCAw
IDFweCAycHggcmdiYSgwLDAsMCwwLjEpOy1tb3otYm94LXNoYWRvdzppbnNldCAwIDFweCAycHggcmdi
YSgwLDAsMCwwLjEpO2JveC1zaGFkb3c6aW5zZXQgMCAxcHggMnB4IHJnYmEoMCwwLDAsMC4xKX0ucHJv
Z3Jlc3MgLmJhcntmbG9hdDpsZWZ0O3dpZHRoOjA7aGVpZ2h0OjEwMCU7Zm9udC1zaXplOjEycHg7Y29s
b3I6I2ZmZjt0ZXh0LWFsaWduOmNlbnRlcjt0ZXh0LXNoYWRvdzowIC0xcHggMCByZ2JhKDAsMCwwLDAu
MjUpO2JhY2tncm91bmQtY29sb3I6IzBlOTBkMjtiYWNrZ3JvdW5kLWltYWdlOi1tb3otbGluZWFyLWdy
YWRpZW50KHRvcCwjMTQ5YmRmLCMwNDgwYmUpO2JhY2tncm91bmQtaW1hZ2U6LXdlYmtpdC1ncmFkaWVu
dChsaW5lYXIsMCAwLDAgMTAwJSxmcm9tKCMxNDliZGYpLHRvKCMwNDgwYmUpKTtiYWNrZ3JvdW5kLWlt
YWdlOi13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwjMTQ5YmRmLCMwNDgwYmUpO2JhY2tncm91bmQt
aW1hZ2U6LW8tbGluZWFyLWdyYWRpZW50KHRvcCwjMTQ5YmRmLCMwNDgwYmUpO2JhY2tncm91bmQtaW1h
Z2U6bGluZWFyLWdyYWRpZW50KHRvIGJvdHRvbSwjMTQ5YmRmLCMwNDgwYmUpO2JhY2tncm91bmQtcmVw
ZWF0OnJlcGVhdC14O2ZpbHRlcjpwcm9naWQ6RFhJbWFnZVRyYW5zZm9ybS5NaWNyb3NvZnQuZ3JhZGll
bnQoc3RhcnRDb2xvcnN0cj0nI2ZmMTQ5YmRmJyxlbmRDb2xvcnN0cj0nI2ZmMDQ4MGJlJyxHcmFkaWVu
dFR5cGU9MCk7LXdlYmtpdC1ib3gtc2hhZG93Omluc2V0IDAgLTFweCAwIHJnYmEoMCwwLDAsMC4xNSk7
LW1vei1ib3gtc2hhZG93Omluc2V0IDAgLTFweCAwIHJnYmEoMCwwLDAsMC4xNSk7Ym94LXNoYWRvdzpp
bnNldCAwIC0xcHggMCByZ2JhKDAsMCwwLDAuMTUpOy13ZWJraXQtYm94LXNpemluZzpib3JkZXItYm94
Oy1tb3otYm94LXNpemluZzpib3JkZXItYm94O2JveC1zaXppbmc6Ym9yZGVyLWJveDstd2Via2l0LXRy
YW5zaXRpb246d2lkdGggLjZzIGVhc2U7LW1vei10cmFuc2l0aW9uOndpZHRoIC42cyBlYXNlOy1vLXRy
YW5zaXRpb246d2lkdGggLjZzIGVhc2U7dHJhbnNpdGlvbjp3aWR0aCAuNnMgZWFzZX0ucHJvZ3Jlc3Mg
LmJhcisuYmFyey13ZWJraXQtYm94LXNoYWRvdzppbnNldCAxcHggMCAwIHJnYmEoMCwwLDAsMC4xNSks
aW5zZXQgMCAtMXB4IDAgcmdiYSgwLDAsMCwwLjE1KTstbW96LWJveC1zaGFkb3c6aW5zZXQgMXB4IDAg
MCByZ2JhKDAsMCwwLDAuMTUpLGluc2V0IDAgLTFweCAwIHJnYmEoMCwwLDAsMC4xNSk7Ym94LXNoYWRv
dzppbnNldCAxcHggMCAwIHJnYmEoMCwwLDAsMC4xNSksaW5zZXQgMCAtMXB4IDAgcmdiYSgwLDAsMCww
LjE1KX0ucHJvZ3Jlc3Mtc3RyaXBlZCAuYmFye2JhY2tncm91bmQtY29sb3I6IzE0OWJkZjtiYWNrZ3Jv
dW5kLWltYWdlOi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMTAwJSwxMDAlIDAsY29sb3Itc3RvcCgw
LjI1LHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0b3AoMC4yNSx0cmFuc3BhcmVudCksY29s
b3Itc3RvcCgwLjUsdHJhbnNwYXJlbnQpLGNvbG9yLXN0b3AoMC41LHJnYmEoMjU1LDI1NSwyNTUsMC4x
NSkpLGNvbG9yLXN0b3AoMC43NSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpKSxjb2xvci1zdG9wKDAuNzUs
dHJhbnNwYXJlbnQpLHRvKHRyYW5zcGFyZW50KSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVh
ci1ncmFkaWVudCg0NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFuc3BhcmVudCAyNSUs
dHJhbnNwYXJlbnQgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEoMjU1LDI1NSwyNTUs
MC4xNSkgNzUlLHRyYW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFja2dyb3VuZC1pbWFnZTotbW96
LWxpbmVhci1ncmFkaWVudCg0NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFuc3BhcmVu
dCAyNSUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEoMjU1LDI1
NSwyNTUsMC4xNSkgNzUlLHRyYW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFja2dyb3VuZC1pbWFn
ZTotby1saW5lYXItZ3JhZGllbnQoNDVkZWcscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSAyNSUsdHJhbnNw
YXJlbnQgMjUlLHRyYW5zcGFyZW50IDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDUwJSxyZ2JhKDI1
NSwyNTUsMjU1LDAuMTUpIDc1JSx0cmFuc3BhcmVudCA3NSUsdHJhbnNwYXJlbnQpO2JhY2tncm91bmQt
aW1hZ2U6bGluZWFyLWdyYWRpZW50KDQ1ZGVnLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgMjUlLHRyYW5z
cGFyZW50IDI1JSx0cmFuc3BhcmVudCA1MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSA1MCUscmdiYSgy
NTUsMjU1LDI1NSwwLjE1KSA3NSUsdHJhbnNwYXJlbnQgNzUlLHRyYW5zcGFyZW50KTstd2Via2l0LWJh
Y2tncm91bmQtc2l6ZTo0MHB4IDQwcHg7LW1vei1iYWNrZ3JvdW5kLXNpemU6NDBweCA0MHB4Oy1vLWJh
Y2tncm91bmQtc2l6ZTo0MHB4IDQwcHg7YmFja2dyb3VuZC1zaXplOjQwcHggNDBweH0ucHJvZ3Jlc3Mu
YWN0aXZlIC5iYXJ7LXdlYmtpdC1hbmltYXRpb246cHJvZ3Jlc3MtYmFyLXN0cmlwZXMgMnMgbGluZWFy
IGluZmluaXRlOy1tb3otYW5pbWF0aW9uOnByb2dyZXNzLWJhci1zdHJpcGVzIDJzIGxpbmVhciBpbmZp
bml0ZTstbXMtYW5pbWF0aW9uOnByb2dyZXNzLWJhci1zdHJpcGVzIDJzIGxpbmVhciBpbmZpbml0ZTst
by1hbmltYXRpb246cHJvZ3Jlc3MtYmFyLXN0cmlwZXMgMnMgbGluZWFyIGluZmluaXRlO2FuaW1hdGlv
bjpwcm9ncmVzcy1iYXItc3RyaXBlcyAycyBsaW5lYXIgaW5maW5pdGV9LnByb2dyZXNzLWRhbmdlciAu
YmFyLC5wcm9ncmVzcyAuYmFyLWRhbmdlcntiYWNrZ3JvdW5kLWNvbG9yOiNkZDUxNGM7YmFja2dyb3Vu
ZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVudCh0b3AsI2VlNWY1YiwjYzQzYzM1KTtiYWNrZ3JvdW5k
LWltYWdlOi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMCwwIDEwMCUsZnJvbSgjZWU1ZjViKSx0bygj
YzQzYzM1KSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsI2VlNWY1
YiwjYzQzYzM1KTtiYWNrZ3JvdW5kLWltYWdlOi1vLWxpbmVhci1ncmFkaWVudCh0b3AsI2VlNWY1Yiwj
YzQzYzM1KTtiYWNrZ3JvdW5kLWltYWdlOmxpbmVhci1ncmFkaWVudCh0byBib3R0b20sI2VlNWY1Yiwj
YzQzYzM1KTtiYWNrZ3JvdW5kLXJlcGVhdDpyZXBlYXQteDtmaWx0ZXI6cHJvZ2lkOkRYSW1hZ2VUcmFu
c2Zvcm0uTWljcm9zb2Z0LmdyYWRpZW50KHN0YXJ0Q29sb3JzdHI9JyNmZmVlNWY1YicsZW5kQ29sb3Jz
dHI9JyNmZmM0M2MzNScsR3JhZGllbnRUeXBlPTApfS5wcm9ncmVzcy1kYW5nZXIucHJvZ3Jlc3Mtc3Ry
aXBlZCAuYmFyLC5wcm9ncmVzcy1zdHJpcGVkIC5iYXItZGFuZ2Vye2JhY2tncm91bmQtY29sb3I6I2Vl
NWY1YjtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMTAwJSwxMDAlIDAs
Y29sb3Itc3RvcCgwLjI1LHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0b3AoMC4yNSx0cmFu
c3BhcmVudCksY29sb3Itc3RvcCgwLjUsdHJhbnNwYXJlbnQpLGNvbG9yLXN0b3AoMC41LHJnYmEoMjU1
LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0b3AoMC43NSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpKSxjb2xv
ci1zdG9wKDAuNzUsdHJhbnNwYXJlbnQpLHRvKHRyYW5zcGFyZW50KSk7YmFja2dyb3VuZC1pbWFnZTot
d2Via2l0LWxpbmVhci1ncmFkaWVudCg0NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFu
c3BhcmVudCAyNSUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEo
MjU1LDI1NSwyNTUsMC4xNSkgNzUlLHRyYW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFja2dyb3Vu
ZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVudCg0NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1
JSx0cmFuc3BhcmVudCAyNSUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAl
LHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNzUlLHRyYW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFj
a2dyb3VuZC1pbWFnZTotby1saW5lYXItZ3JhZGllbnQoNDVkZWcscmdiYSgyNTUsMjU1LDI1NSwwLjE1
KSAyNSUsdHJhbnNwYXJlbnQgMjUlLHRyYW5zcGFyZW50IDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUp
IDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDc1JSx0cmFuc3BhcmVudCA3NSUsdHJhbnNwYXJlbnQp
O2JhY2tncm91bmQtaW1hZ2U6bGluZWFyLWdyYWRpZW50KDQ1ZGVnLHJnYmEoMjU1LDI1NSwyNTUsMC4x
NSkgMjUlLHRyYW5zcGFyZW50IDI1JSx0cmFuc3BhcmVudCA1MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1
KSA1MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSA3NSUsdHJhbnNwYXJlbnQgNzUlLHRyYW5zcGFyZW50
KX0ucHJvZ3Jlc3Mtc3VjY2VzcyAuYmFyLC5wcm9ncmVzcyAuYmFyLXN1Y2Nlc3N7YmFja2dyb3VuZC1j
b2xvcjojNWViOTVlO2JhY2tncm91bmQtaW1hZ2U6LW1vei1saW5lYXItZ3JhZGllbnQodG9wLCM2MmM0
NjIsIzU3YTk1Nyk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWdyYWRpZW50KGxpbmVhciwwIDAsMCAx
MDAlLGZyb20oIzYyYzQ2MiksdG8oIzU3YTk1NykpO2JhY2tncm91bmQtaW1hZ2U6LXdlYmtpdC1saW5l
YXItZ3JhZGllbnQodG9wLCM2MmM0NjIsIzU3YTk1Nyk7YmFja2dyb3VuZC1pbWFnZTotby1saW5lYXIt
Z3JhZGllbnQodG9wLCM2MmM0NjIsIzU3YTk1Nyk7YmFja2dyb3VuZC1pbWFnZTpsaW5lYXItZ3JhZGll
bnQodG8gYm90dG9tLCM2MmM0NjIsIzU3YTk1Nyk7YmFja2dyb3VuZC1yZXBlYXQ6cmVwZWF0LXg7Zmls
dGVyOnByb2dpZDpEWEltYWdlVHJhbnNmb3JtLk1pY3Jvc29mdC5ncmFkaWVudChzdGFydENvbG9yc3Ry
PScjZmY2MmM0NjInLGVuZENvbG9yc3RyPScjZmY1N2E5NTcnLEdyYWRpZW50VHlwZT0wKX0ucHJvZ3Jl
c3Mtc3VjY2Vzcy5wcm9ncmVzcy1zdHJpcGVkIC5iYXIsLnByb2dyZXNzLXN0cmlwZWQgLmJhci1zdWNj
ZXNze2JhY2tncm91bmQtY29sb3I6IzYyYzQ2MjtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtZ3JhZGll
bnQobGluZWFyLDAgMTAwJSwxMDAlIDAsY29sb3Itc3RvcCgwLjI1LHJnYmEoMjU1LDI1NSwyNTUsMC4x
NSkpLGNvbG9yLXN0b3AoMC4yNSx0cmFuc3BhcmVudCksY29sb3Itc3RvcCgwLjUsdHJhbnNwYXJlbnQp
LGNvbG9yLXN0b3AoMC41LHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0b3AoMC43NSxyZ2Jh
KDI1NSwyNTUsMjU1LDAuMTUpKSxjb2xvci1zdG9wKDAuNzUsdHJhbnNwYXJlbnQpLHRvKHRyYW5zcGFy
ZW50KSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCg0NWRlZyxyZ2JhKDI1
NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFuc3BhcmVudCAyNSUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMjU1
LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNzUlLHRyYW5zcGFyZW50IDc1
JSx0cmFuc3BhcmVudCk7YmFja2dyb3VuZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVudCg0NWRlZyxy
Z2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFuc3BhcmVudCAyNSUsdHJhbnNwYXJlbnQgNTAlLHJn
YmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNzUlLHRyYW5zcGFy
ZW50IDc1JSx0cmFuc3BhcmVudCk7YmFja2dyb3VuZC1pbWFnZTotby1saW5lYXItZ3JhZGllbnQoNDVk
ZWcscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSAyNSUsdHJhbnNwYXJlbnQgMjUlLHRyYW5zcGFyZW50IDUw
JSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDc1JSx0cmFu
c3BhcmVudCA3NSUsdHJhbnNwYXJlbnQpO2JhY2tncm91bmQtaW1hZ2U6bGluZWFyLWdyYWRpZW50KDQ1
ZGVnLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgMjUlLHRyYW5zcGFyZW50IDI1JSx0cmFuc3BhcmVudCA1
MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSA1MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSA3NSUsdHJh
bnNwYXJlbnQgNzUlLHRyYW5zcGFyZW50KX0ucHJvZ3Jlc3MtaW5mbyAuYmFyLC5wcm9ncmVzcyAuYmFy
LWluZm97YmFja2dyb3VuZC1jb2xvcjojNGJiMWNmO2JhY2tncm91bmQtaW1hZ2U6LW1vei1saW5lYXIt
Z3JhZGllbnQodG9wLCM1YmMwZGUsIzMzOWJiOSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWdyYWRp
ZW50KGxpbmVhciwwIDAsMCAxMDAlLGZyb20oIzViYzBkZSksdG8oIzMzOWJiOSkpO2JhY2tncm91bmQt
aW1hZ2U6LXdlYmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCM1YmMwZGUsIzMzOWJiOSk7YmFja2dyb3Vu
ZC1pbWFnZTotby1saW5lYXItZ3JhZGllbnQodG9wLCM1YmMwZGUsIzMzOWJiOSk7YmFja2dyb3VuZC1p
bWFnZTpsaW5lYXItZ3JhZGllbnQodG8gYm90dG9tLCM1YmMwZGUsIzMzOWJiOSk7YmFja2dyb3VuZC1y
ZXBlYXQ6cmVwZWF0LXg7ZmlsdGVyOnByb2dpZDpEWEltYWdlVHJhbnNmb3JtLk1pY3Jvc29mdC5ncmFk
aWVudChzdGFydENvbG9yc3RyPScjZmY1YmMwZGUnLGVuZENvbG9yc3RyPScjZmYzMzliYjknLEdyYWRp
ZW50VHlwZT0wKX0ucHJvZ3Jlc3MtaW5mby5wcm9ncmVzcy1zdHJpcGVkIC5iYXIsLnByb2dyZXNzLXN0
cmlwZWQgLmJhci1pbmZve2JhY2tncm91bmQtY29sb3I6IzViYzBkZTtiYWNrZ3JvdW5kLWltYWdlOi13
ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMTAwJSwxMDAlIDAsY29sb3Itc3RvcCgwLjI1LHJnYmEoMjU1
LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0b3AoMC4yNSx0cmFuc3BhcmVudCksY29sb3Itc3RvcCgwLjUs
dHJhbnNwYXJlbnQpLGNvbG9yLXN0b3AoMC41LHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0
b3AoMC43NSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpKSxjb2xvci1zdG9wKDAuNzUsdHJhbnNwYXJlbnQp
LHRvKHRyYW5zcGFyZW50KSk7YmFja2dyb3VuZC1pbWFnZTotd2Via2l0LWxpbmVhci1ncmFkaWVudCg0
NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFuc3BhcmVudCAyNSUsdHJhbnNwYXJlbnQg
NTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNzUlLHRy
YW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFja2dyb3VuZC1pbWFnZTotbW96LWxpbmVhci1ncmFk
aWVudCg0NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFuc3BhcmVudCAyNSUsdHJhbnNw
YXJlbnQgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkg
NzUlLHRyYW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFja2dyb3VuZC1pbWFnZTotby1saW5lYXIt
Z3JhZGllbnQoNDVkZWcscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSAyNSUsdHJhbnNwYXJlbnQgMjUlLHRy
YW5zcGFyZW50IDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAu
MTUpIDc1JSx0cmFuc3BhcmVudCA3NSUsdHJhbnNwYXJlbnQpO2JhY2tncm91bmQtaW1hZ2U6bGluZWFy
LWdyYWRpZW50KDQ1ZGVnLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgMjUlLHRyYW5zcGFyZW50IDI1JSx0
cmFuc3BhcmVudCA1MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSA1MCUscmdiYSgyNTUsMjU1LDI1NSww
LjE1KSA3NSUsdHJhbnNwYXJlbnQgNzUlLHRyYW5zcGFyZW50KX0ucHJvZ3Jlc3Mtd2FybmluZyAuYmFy
LC5wcm9ncmVzcyAuYmFyLXdhcm5pbmd7YmFja2dyb3VuZC1jb2xvcjojZmFhNzMyO2JhY2tncm91bmQt
aW1hZ2U6LW1vei1saW5lYXItZ3JhZGllbnQodG9wLCNmYmI0NTAsI2Y4OTQwNik7YmFja2dyb3VuZC1p
bWFnZTotd2Via2l0LWdyYWRpZW50KGxpbmVhciwwIDAsMCAxMDAlLGZyb20oI2ZiYjQ1MCksdG8oI2Y4
OTQwNikpO2JhY2tncm91bmQtaW1hZ2U6LXdlYmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCNmYmI0NTAs
I2Y4OTQwNik7YmFja2dyb3VuZC1pbWFnZTotby1saW5lYXItZ3JhZGllbnQodG9wLCNmYmI0NTAsI2Y4
OTQwNik7YmFja2dyb3VuZC1pbWFnZTpsaW5lYXItZ3JhZGllbnQodG8gYm90dG9tLCNmYmI0NTAsI2Y4
OTQwNik7YmFja2dyb3VuZC1yZXBlYXQ6cmVwZWF0LXg7ZmlsdGVyOnByb2dpZDpEWEltYWdlVHJhbnNm
b3JtLk1pY3Jvc29mdC5ncmFkaWVudChzdGFydENvbG9yc3RyPScjZmZmYmI0NTAnLGVuZENvbG9yc3Ry
PScjZmZmODk0MDYnLEdyYWRpZW50VHlwZT0wKX0ucHJvZ3Jlc3Mtd2FybmluZy5wcm9ncmVzcy1zdHJp
cGVkIC5iYXIsLnByb2dyZXNzLXN0cmlwZWQgLmJhci13YXJuaW5ne2JhY2tncm91bmQtY29sb3I6I2Zi
YjQ1MDtiYWNrZ3JvdW5kLWltYWdlOi13ZWJraXQtZ3JhZGllbnQobGluZWFyLDAgMTAwJSwxMDAlIDAs
Y29sb3Itc3RvcCgwLjI1LHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0b3AoMC4yNSx0cmFu
c3BhcmVudCksY29sb3Itc3RvcCgwLjUsdHJhbnNwYXJlbnQpLGNvbG9yLXN0b3AoMC41LHJnYmEoMjU1
LDI1NSwyNTUsMC4xNSkpLGNvbG9yLXN0b3AoMC43NSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpKSxjb2xv
ci1zdG9wKDAuNzUsdHJhbnNwYXJlbnQpLHRvKHRyYW5zcGFyZW50KSk7YmFja2dyb3VuZC1pbWFnZTot
d2Via2l0LWxpbmVhci1ncmFkaWVudCg0NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1JSx0cmFu
c3BhcmVudCAyNSUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAlLHJnYmEo
MjU1LDI1NSwyNTUsMC4xNSkgNzUlLHRyYW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFja2dyb3Vu
ZC1pbWFnZTotbW96LWxpbmVhci1ncmFkaWVudCg0NWRlZyxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDI1
JSx0cmFuc3BhcmVudCAyNSUsdHJhbnNwYXJlbnQgNTAlLHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNTAl
LHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgNzUlLHRyYW5zcGFyZW50IDc1JSx0cmFuc3BhcmVudCk7YmFj
a2dyb3VuZC1pbWFnZTotby1saW5lYXItZ3JhZGllbnQoNDVkZWcscmdiYSgyNTUsMjU1LDI1NSwwLjE1
KSAyNSUsdHJhbnNwYXJlbnQgMjUlLHRyYW5zcGFyZW50IDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUp
IDUwJSxyZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDc1JSx0cmFuc3BhcmVudCA3NSUsdHJhbnNwYXJlbnQp
O2JhY2tncm91bmQtaW1hZ2U6bGluZWFyLWdyYWRpZW50KDQ1ZGVnLHJnYmEoMjU1LDI1NSwyNTUsMC4x
NSkgMjUlLHRyYW5zcGFyZW50IDI1JSx0cmFuc3BhcmVudCA1MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1
KSA1MCUscmdiYSgyNTUsMjU1LDI1NSwwLjE1KSA3NSUsdHJhbnNwYXJlbnQgNzUlLHRyYW5zcGFyZW50
KX0uYWNjb3JkaW9ue21hcmdpbi1ib3R0b206MjBweH0uYWNjb3JkaW9uLWdyb3Vwe21hcmdpbi1ib3R0
b206MnB4O2JvcmRlcjoxcHggc29saWQgI2U1ZTVlNTstd2Via2l0LWJvcmRlci1yYWRpdXM6NHB4Oy1t
b3otYm9yZGVyLXJhZGl1czo0cHg7Ym9yZGVyLXJhZGl1czo0cHh9LmFjY29yZGlvbi1oZWFkaW5ne2Jv
cmRlci1ib3R0b206MH0uYWNjb3JkaW9uLWhlYWRpbmcgLmFjY29yZGlvbi10b2dnbGV7ZGlzcGxheTpi
bG9jaztwYWRkaW5nOjhweCAxNXB4fS5hY2NvcmRpb24tdG9nZ2xle2N1cnNvcjpwb2ludGVyfS5hY2Nv
cmRpb24taW5uZXJ7cGFkZGluZzo5cHggMTVweDtib3JkZXItdG9wOjFweCBzb2xpZCAjZTVlNWU1fS5j
YXJvdXNlbHtwb3NpdGlvbjpyZWxhdGl2ZTttYXJnaW4tYm90dG9tOjIwcHg7bGluZS1oZWlnaHQ6MX0u
Y2Fyb3VzZWwtaW5uZXJ7cG9zaXRpb246cmVsYXRpdmU7d2lkdGg6MTAwJTtvdmVyZmxvdzpoaWRkZW59
LmNhcm91c2VsLWlubmVyPi5pdGVte3Bvc2l0aW9uOnJlbGF0aXZlO2Rpc3BsYXk6bm9uZTstd2Via2l0
LXRyYW5zaXRpb246LjZzIGVhc2UtaW4tb3V0IGxlZnQ7LW1vei10cmFuc2l0aW9uOi42cyBlYXNlLWlu
LW91dCBsZWZ0Oy1vLXRyYW5zaXRpb246LjZzIGVhc2UtaW4tb3V0IGxlZnQ7dHJhbnNpdGlvbjouNnMg
ZWFzZS1pbi1vdXQgbGVmdH0uY2Fyb3VzZWwtaW5uZXI+Lml0ZW0+aW1nLC5jYXJvdXNlbC1pbm5lcj4u
aXRlbT5hPmltZ3tkaXNwbGF5OmJsb2NrO2xpbmUtaGVpZ2h0OjF9LmNhcm91c2VsLWlubmVyPi5hY3Rp
dmUsLmNhcm91c2VsLWlubmVyPi5uZXh0LC5jYXJvdXNlbC1pbm5lcj4ucHJldntkaXNwbGF5OmJsb2Nr
fS5jYXJvdXNlbC1pbm5lcj4uYWN0aXZle2xlZnQ6MH0uY2Fyb3VzZWwtaW5uZXI+Lm5leHQsLmNhcm91
c2VsLWlubmVyPi5wcmV2e3Bvc2l0aW9uOmFic29sdXRlO3RvcDowO3dpZHRoOjEwMCV9LmNhcm91c2Vs
LWlubmVyPi5uZXh0e2xlZnQ6MTAwJX0uY2Fyb3VzZWwtaW5uZXI+LnByZXZ7bGVmdDotMTAwJX0uY2Fy
b3VzZWwtaW5uZXI+Lm5leHQubGVmdCwuY2Fyb3VzZWwtaW5uZXI+LnByZXYucmlnaHR7bGVmdDowfS5j
YXJvdXNlbC1pbm5lcj4uYWN0aXZlLmxlZnR7bGVmdDotMTAwJX0uY2Fyb3VzZWwtaW5uZXI+LmFjdGl2
ZS5yaWdodHtsZWZ0OjEwMCV9LmNhcm91c2VsLWNvbnRyb2x7cG9zaXRpb246YWJzb2x1dGU7dG9wOjQw
JTtsZWZ0OjE1cHg7d2lkdGg6NDBweDtoZWlnaHQ6NDBweDttYXJnaW4tdG9wOi0yMHB4O2ZvbnQtc2l6
ZTo2MHB4O2ZvbnQtd2VpZ2h0OjEwMDtsaW5lLWhlaWdodDozMHB4O2NvbG9yOiNmZmY7dGV4dC1hbGln
bjpjZW50ZXI7YmFja2dyb3VuZDojMjIyO2JvcmRlcjozcHggc29saWQgI2ZmZjstd2Via2l0LWJvcmRl
ci1yYWRpdXM6MjNweDstbW96LWJvcmRlci1yYWRpdXM6MjNweDtib3JkZXItcmFkaXVzOjIzcHg7b3Bh
Y2l0eTouNTtmaWx0ZXI6YWxwaGEob3BhY2l0eT01MCl9LmNhcm91c2VsLWNvbnRyb2wucmlnaHR7cmln
aHQ6MTVweDtsZWZ0OmF1dG99LmNhcm91c2VsLWNvbnRyb2w6aG92ZXIsLmNhcm91c2VsLWNvbnRyb2w6
Zm9jdXN7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTtvcGFjaXR5Oi45O2ZpbHRlcjphbHBo
YShvcGFjaXR5PTkwKX0uY2Fyb3VzZWwtaW5kaWNhdG9yc3twb3NpdGlvbjphYnNvbHV0ZTt0b3A6MTVw
eDtyaWdodDoxNXB4O3otaW5kZXg6NTttYXJnaW46MDtsaXN0LXN0eWxlOm5vbmV9LmNhcm91c2VsLWlu
ZGljYXRvcnMgbGl7ZGlzcGxheTpibG9jaztmbG9hdDpsZWZ0O3dpZHRoOjEwcHg7aGVpZ2h0OjEwcHg7
bWFyZ2luLWxlZnQ6NXB4O3RleHQtaW5kZW50Oi05OTlweDtiYWNrZ3JvdW5kLWNvbG9yOiNjY2M7YmFj
a2dyb3VuZC1jb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMjUpO2JvcmRlci1yYWRpdXM6NXB4fS5jYXJv
dXNlbC1pbmRpY2F0b3JzIC5hY3RpdmV7YmFja2dyb3VuZC1jb2xvcjojZmZmfS5jYXJvdXNlbC1jYXB0
aW9ue3Bvc2l0aW9uOmFic29sdXRlO3JpZ2h0OjA7Ym90dG9tOjA7bGVmdDowO3BhZGRpbmc6MTVweDti
YWNrZ3JvdW5kOiMzMzM7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNzUpfS5jYXJvdXNlbC1jYXB0aW9u
IGg0LC5jYXJvdXNlbC1jYXB0aW9uIHB7bGluZS1oZWlnaHQ6MjBweDtjb2xvcjojZmZmfS5jYXJvdXNl
bC1jYXB0aW9uIGg0e21hcmdpbjowIDAgNXB4fS5jYXJvdXNlbC1jYXB0aW9uIHB7bWFyZ2luLWJvdHRv
bTowfS5oZXJvLXVuaXR7cGFkZGluZzo2MHB4O21hcmdpbi1ib3R0b206MzBweDtmb250LXNpemU6MThw
eDtmb250LXdlaWdodDoyMDA7bGluZS1oZWlnaHQ6MzBweDtjb2xvcjppbmhlcml0O2JhY2tncm91bmQt
Y29sb3I6I2VlZTstd2Via2l0LWJvcmRlci1yYWRpdXM6NnB4Oy1tb3otYm9yZGVyLXJhZGl1czo2cHg7
Ym9yZGVyLXJhZGl1czo2cHh9Lmhlcm8tdW5pdCBoMXttYXJnaW4tYm90dG9tOjA7Zm9udC1zaXplOjYw
cHg7bGluZS1oZWlnaHQ6MTtsZXR0ZXItc3BhY2luZzotMXB4O2NvbG9yOmluaGVyaXR9Lmhlcm8tdW5p
dCBsaXtsaW5lLWhlaWdodDozMHB4fS5wdWxsLXJpZ2h0e2Zsb2F0OnJpZ2h0fS5wdWxsLWxlZnR7Zmxv
YXQ6bGVmdH0uaGlkZXtkaXNwbGF5Om5vbmV9LnNob3d7ZGlzcGxheTpibG9ja30uaW52aXNpYmxle3Zp
c2liaWxpdHk6aGlkZGVufS5hZmZpeHtwb3NpdGlvbjpmaXhlZH0K

@@ bootstrap_resp_min_css
LyohCiAqIEJvb3RzdHJhcCBSZXNwb25zaXZlIHYyLjMuMAogKgogKiBDb3B5cmlnaHQgMjAxMiBUd2l0
dGVyLCBJbmMKICogTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlIHYyLjAKICogaHR0cDov
L3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wCiAqCiAqIERlc2lnbmVkIGFuZCBidWls
dCB3aXRoIGFsbCB0aGUgbG92ZSBpbiB0aGUgd29ybGQgQHR3aXR0ZXIgYnkgQG1kbyBhbmQgQGZhdC4K
ICovLmNsZWFyZml4eyp6b29tOjF9LmNsZWFyZml4OmJlZm9yZSwuY2xlYXJmaXg6YWZ0ZXJ7ZGlzcGxh
eTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9LmNsZWFyZml4OmFmdGVye2NsZWFyOmJvdGh9
LmhpZGUtdGV4dHtmb250OjAvMCBhO2NvbG9yOnRyYW5zcGFyZW50O3RleHQtc2hhZG93Om5vbmU7YmFj
a2dyb3VuZC1jb2xvcjp0cmFuc3BhcmVudDtib3JkZXI6MH0uaW5wdXQtYmxvY2stbGV2ZWx7ZGlzcGxh
eTpibG9jazt3aWR0aDoxMDAlO21pbi1oZWlnaHQ6MzBweDstd2Via2l0LWJveC1zaXppbmc6Ym9yZGVy
LWJveDstbW96LWJveC1zaXppbmc6Ym9yZGVyLWJveDtib3gtc2l6aW5nOmJvcmRlci1ib3h9QC1tcy12
aWV3cG9ydHt3aWR0aDpkZXZpY2Utd2lkdGh9LmhpZGRlbntkaXNwbGF5Om5vbmU7dmlzaWJpbGl0eTpo
aWRkZW59LnZpc2libGUtcGhvbmV7ZGlzcGxheTpub25lIWltcG9ydGFudH0udmlzaWJsZS10YWJsZXR7
ZGlzcGxheTpub25lIWltcG9ydGFudH0uaGlkZGVuLWRlc2t0b3B7ZGlzcGxheTpub25lIWltcG9ydGFu
dH0udmlzaWJsZS1kZXNrdG9we2Rpc3BsYXk6aW5oZXJpdCFpbXBvcnRhbnR9QG1lZGlhKG1pbi13aWR0
aDo3NjhweCkgYW5kIChtYXgtd2lkdGg6OTc5cHgpey5oaWRkZW4tZGVza3RvcHtkaXNwbGF5OmluaGVy
aXQhaW1wb3J0YW50fS52aXNpYmxlLWRlc2t0b3B7ZGlzcGxheTpub25lIWltcG9ydGFudH0udmlzaWJs
ZS10YWJsZXR7ZGlzcGxheTppbmhlcml0IWltcG9ydGFudH0uaGlkZGVuLXRhYmxldHtkaXNwbGF5Om5v
bmUhaW1wb3J0YW50fX1AbWVkaWEobWF4LXdpZHRoOjc2N3B4KXsuaGlkZGVuLWRlc2t0b3B7ZGlzcGxh
eTppbmhlcml0IWltcG9ydGFudH0udmlzaWJsZS1kZXNrdG9we2Rpc3BsYXk6bm9uZSFpbXBvcnRhbnR9
LnZpc2libGUtcGhvbmV7ZGlzcGxheTppbmhlcml0IWltcG9ydGFudH0uaGlkZGVuLXBob25le2Rpc3Bs
YXk6bm9uZSFpbXBvcnRhbnR9fS52aXNpYmxlLXByaW50e2Rpc3BsYXk6bm9uZSFpbXBvcnRhbnR9QG1l
ZGlhIHByaW50ey52aXNpYmxlLXByaW50e2Rpc3BsYXk6aW5oZXJpdCFpbXBvcnRhbnR9LmhpZGRlbi1w
cmludHtkaXNwbGF5Om5vbmUhaW1wb3J0YW50fX1AbWVkaWEobWluLXdpZHRoOjEyMDBweCl7LnJvd3tt
YXJnaW4tbGVmdDotMzBweDsqem9vbToxfS5yb3c6YmVmb3JlLC5yb3c6YWZ0ZXJ7ZGlzcGxheTp0YWJs
ZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9LnJvdzphZnRlcntjbGVhcjpib3RofVtjbGFzcyo9InNw
YW4iXXtmbG9hdDpsZWZ0O21pbi1oZWlnaHQ6MXB4O21hcmdpbi1sZWZ0OjMwcHh9LmNvbnRhaW5lciwu
bmF2YmFyLXN0YXRpYy10b3AgLmNvbnRhaW5lciwubmF2YmFyLWZpeGVkLXRvcCAuY29udGFpbmVyLC5u
YXZiYXItZml4ZWQtYm90dG9tIC5jb250YWluZXJ7d2lkdGg6MTE3MHB4fS5zcGFuMTJ7d2lkdGg6MTE3
MHB4fS5zcGFuMTF7d2lkdGg6MTA3MHB4fS5zcGFuMTB7d2lkdGg6OTcwcHh9LnNwYW45e3dpZHRoOjg3
MHB4fS5zcGFuOHt3aWR0aDo3NzBweH0uc3Bhbjd7d2lkdGg6NjcwcHh9LnNwYW42e3dpZHRoOjU3MHB4
fS5zcGFuNXt3aWR0aDo0NzBweH0uc3BhbjR7d2lkdGg6MzcwcHh9LnNwYW4ze3dpZHRoOjI3MHB4fS5z
cGFuMnt3aWR0aDoxNzBweH0uc3BhbjF7d2lkdGg6NzBweH0ub2Zmc2V0MTJ7bWFyZ2luLWxlZnQ6MTIz
MHB4fS5vZmZzZXQxMXttYXJnaW4tbGVmdDoxMTMwcHh9Lm9mZnNldDEwe21hcmdpbi1sZWZ0OjEwMzBw
eH0ub2Zmc2V0OXttYXJnaW4tbGVmdDo5MzBweH0ub2Zmc2V0OHttYXJnaW4tbGVmdDo4MzBweH0ub2Zm
c2V0N3ttYXJnaW4tbGVmdDo3MzBweH0ub2Zmc2V0NnttYXJnaW4tbGVmdDo2MzBweH0ub2Zmc2V0NXtt
YXJnaW4tbGVmdDo1MzBweH0ub2Zmc2V0NHttYXJnaW4tbGVmdDo0MzBweH0ub2Zmc2V0M3ttYXJnaW4t
bGVmdDozMzBweH0ub2Zmc2V0MnttYXJnaW4tbGVmdDoyMzBweH0ub2Zmc2V0MXttYXJnaW4tbGVmdDox
MzBweH0ucm93LWZsdWlke3dpZHRoOjEwMCU7Knpvb206MX0ucm93LWZsdWlkOmJlZm9yZSwucm93LWZs
dWlkOmFmdGVye2Rpc3BsYXk6dGFibGU7bGluZS1oZWlnaHQ6MDtjb250ZW50OiIifS5yb3ctZmx1aWQ6
YWZ0ZXJ7Y2xlYXI6Ym90aH0ucm93LWZsdWlkIFtjbGFzcyo9InNwYW4iXXtkaXNwbGF5OmJsb2NrO2Zs
b2F0OmxlZnQ7d2lkdGg6MTAwJTttaW4taGVpZ2h0OjMwcHg7bWFyZ2luLWxlZnQ6Mi41NjQxMDI1NjQx
MDI1NjQlOyptYXJnaW4tbGVmdDoyLjUxMDkxMTA3NDc0MDg2MTYlOy13ZWJraXQtYm94LXNpemluZzpi
b3JkZXItYm94Oy1tb3otYm94LXNpemluZzpib3JkZXItYm94O2JveC1zaXppbmc6Ym9yZGVyLWJveH0u
cm93LWZsdWlkIFtjbGFzcyo9InNwYW4iXTpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDowfS5yb3ctZmx1
aWQgLmNvbnRyb2xzLXJvdyBbY2xhc3MqPSJzcGFuIl0rW2NsYXNzKj0ic3BhbiJde21hcmdpbi1sZWZ0
OjIuNTY0MTAyNTY0MTAyNTY0JX0ucm93LWZsdWlkIC5zcGFuMTJ7d2lkdGg6MTAwJTsqd2lkdGg6OTku
OTQ2ODA4NTEwNjM4MjklfS5yb3ctZmx1aWQgLnNwYW4xMXt3aWR0aDo5MS40NTI5OTE0NTI5OTE0NSU7
KndpZHRoOjkxLjM5OTc5OTk2MzYyOTc1JX0ucm93LWZsdWlkIC5zcGFuMTB7d2lkdGg6ODIuOTA1OTgy
OTA1OTgyOTElOyp3aWR0aDo4Mi44NTI3OTE0MTY2MjEyJX0ucm93LWZsdWlkIC5zcGFuOXt3aWR0aDo3
NC4zNTg5NzQzNTg5NzQzNiU7KndpZHRoOjc0LjMwNTc4Mjg2OTYxMjY2JX0ucm93LWZsdWlkIC5zcGFu
OHt3aWR0aDo2NS44MTE5NjU4MTE5NjU4MiU7KndpZHRoOjY1Ljc1ODc3NDMyMjYwNDExJX0ucm93LWZs
dWlkIC5zcGFuN3t3aWR0aDo1Ny4yNjQ5NTcyNjQ5NTcyNiU7KndpZHRoOjU3LjIxMTc2NTc3NTU5NTU2
JX0ucm93LWZsdWlkIC5zcGFuNnt3aWR0aDo0OC43MTc5NDg3MTc5NDg3MTUlOyp3aWR0aDo0OC42NjQ3
NTcyMjg1ODcwMTQlfS5yb3ctZmx1aWQgLnNwYW41e3dpZHRoOjQwLjE3MDk0MDE3MDk0MDE3JTsqd2lk
dGg6NDAuMTE3NzQ4NjgxNTc4NDclfS5yb3ctZmx1aWQgLnNwYW40e3dpZHRoOjMxLjYyMzkzMTYyMzkz
MTYyNSU7KndpZHRoOjMxLjU3MDc0MDEzNDU2OTkyNCV9LnJvdy1mbHVpZCAuc3BhbjN7d2lkdGg6MjMu
MDc2OTIzMDc2OTIzMDc3JTsqd2lkdGg6MjMuMDIzNzMxNTg3NTYxMzc1JX0ucm93LWZsdWlkIC5zcGFu
Mnt3aWR0aDoxNC41Mjk5MTQ1Mjk5MTQ1MyU7KndpZHRoOjE0LjQ3NjcyMzA0MDU1MjgyOCV9LnJvdy1m
bHVpZCAuc3BhbjF7d2lkdGg6NS45ODI5MDU5ODI5MDU5ODMlOyp3aWR0aDo1LjkyOTcxNDQ5MzU0NDI4
MSV9LnJvdy1mbHVpZCAub2Zmc2V0MTJ7bWFyZ2luLWxlZnQ6MTA1LjEyODIwNTEyODIwNTEyJTsqbWFy
Z2luLWxlZnQ6MTA1LjAyMTgyMjE0OTQ4MTcxJX0ucm93LWZsdWlkIC5vZmZzZXQxMjpmaXJzdC1jaGls
ZHttYXJnaW4tbGVmdDoxMDIuNTY0MTAyNTY0MTAyNTclOyptYXJnaW4tbGVmdDoxMDIuNDU3NzE5NTg1
Mzc5MTUlfS5yb3ctZmx1aWQgLm9mZnNldDExe21hcmdpbi1sZWZ0Ojk2LjU4MTE5NjU4MTE5NjU4JTsq
bWFyZ2luLWxlZnQ6OTYuNDc0ODEzNjAyNDczMTYlfS5yb3ctZmx1aWQgLm9mZnNldDExOmZpcnN0LWNo
aWxke21hcmdpbi1sZWZ0Ojk0LjAxNzA5NDAxNzA5NDAyJTsqbWFyZ2luLWxlZnQ6OTMuOTEwNzExMDM4
MzcwNjElfS5yb3ctZmx1aWQgLm9mZnNldDEwe21hcmdpbi1sZWZ0Ojg4LjAzNDE4ODAzNDE4ODAzJTsq
bWFyZ2luLWxlZnQ6ODcuOTI3ODA1MDU1NDY0NjIlfS5yb3ctZmx1aWQgLm9mZnNldDEwOmZpcnN0LWNo
aWxke21hcmdpbi1sZWZ0Ojg1LjQ3MDA4NTQ3MDA4NTQ4JTsqbWFyZ2luLWxlZnQ6ODUuMzYzNzAyNDkx
MzYyMDYlfS5yb3ctZmx1aWQgLm9mZnNldDl7bWFyZ2luLWxlZnQ6NzkuNDg3MTc5NDg3MTc5NDklOypt
YXJnaW4tbGVmdDo3OS4zODA3OTY1MDg0NTYwNyV9LnJvdy1mbHVpZCAub2Zmc2V0OTpmaXJzdC1jaGls
ZHttYXJnaW4tbGVmdDo3Ni45MjMwNzY5MjMwNzY5MyU7Km1hcmdpbi1sZWZ0Ojc2LjgxNjY5Mzk0NDM1
MzUyJX0ucm93LWZsdWlkIC5vZmZzZXQ4e21hcmdpbi1sZWZ0OjcwLjk0MDE3MDk0MDE3MDk0JTsqbWFy
Z2luLWxlZnQ6NzAuODMzNzg3OTYxNDQ3NTMlfS5yb3ctZmx1aWQgLm9mZnNldDg6Zmlyc3QtY2hpbGR7
bWFyZ2luLWxlZnQ6NjguMzc2MDY4Mzc2MDY4MzklOyptYXJnaW4tbGVmdDo2OC4yNjk2ODUzOTczNDQ5
NyV9LnJvdy1mbHVpZCAub2Zmc2V0N3ttYXJnaW4tbGVmdDo2Mi4zOTMxNjIzOTMxNjIzODUlOyptYXJn
aW4tbGVmdDo2Mi4yODY3Nzk0MTQ0Mzg5OSV9LnJvdy1mbHVpZCAub2Zmc2V0NzpmaXJzdC1jaGlsZHtt
YXJnaW4tbGVmdDo1OS44MjkwNTk4MjkwNTk4MiU7Km1hcmdpbi1sZWZ0OjU5LjcyMjY3Njg1MDMzNjQy
JX0ucm93LWZsdWlkIC5vZmZzZXQ2e21hcmdpbi1sZWZ0OjUzLjg0NjE1Mzg0NjE1Mzg0JTsqbWFyZ2lu
LWxlZnQ6NTMuNzM5NzcwODY3NDMwNDQ0JX0ucm93LWZsdWlkIC5vZmZzZXQ2OmZpcnN0LWNoaWxke21h
cmdpbi1sZWZ0OjUxLjI4MjA1MTI4MjA1MTI4JTsqbWFyZ2luLWxlZnQ6NTEuMTc1NjY4MzAzMzI3ODc1
JX0ucm93LWZsdWlkIC5vZmZzZXQ1e21hcmdpbi1sZWZ0OjQ1LjI5OTE0NTI5OTE0NTI5NSU7Km1hcmdp
bi1sZWZ0OjQ1LjE5Mjc2MjMyMDQyMTklfS5yb3ctZmx1aWQgLm9mZnNldDU6Zmlyc3QtY2hpbGR7bWFy
Z2luLWxlZnQ6NDIuNzM1MDQyNzM1MDQyNzMlOyptYXJnaW4tbGVmdDo0Mi42Mjg2NTk3NTYzMTkzMyV9
LnJvdy1mbHVpZCAub2Zmc2V0NHttYXJnaW4tbGVmdDozNi43NTIxMzY3NTIxMzY3NSU7Km1hcmdpbi1s
ZWZ0OjM2LjY0NTc1Mzc3MzQxMzM1NCV9LnJvdy1mbHVpZCAub2Zmc2V0NDpmaXJzdC1jaGlsZHttYXJn
aW4tbGVmdDozNC4xODgwMzQxODgwMzQxOSU7Km1hcmdpbi1sZWZ0OjM0LjA4MTY1MTIwOTMxMDc4NSV9
LnJvdy1mbHVpZCAub2Zmc2V0M3ttYXJnaW4tbGVmdDoyOC4yMDUxMjgyMDUxMjgyMDQlOyptYXJnaW4t
bGVmdDoyOC4wOTg3NDUyMjY0MDQ4JX0ucm93LWZsdWlkIC5vZmZzZXQzOmZpcnN0LWNoaWxke21hcmdp
bi1sZWZ0OjI1LjY0MTAyNTY0MTAyNTY0MiU7Km1hcmdpbi1sZWZ0OjI1LjUzNDY0MjY2MjMwMjI0JX0u
cm93LWZsdWlkIC5vZmZzZXQye21hcmdpbi1sZWZ0OjE5LjY1ODExOTY1ODExOTY2JTsqbWFyZ2luLWxl
ZnQ6MTkuNTUxNzM2Njc5Mzk2MjU3JX0ucm93LWZsdWlkIC5vZmZzZXQyOmZpcnN0LWNoaWxke21hcmdp
bi1sZWZ0OjE3LjA5NDAxNzA5NDAxNzA5NCU7Km1hcmdpbi1sZWZ0OjE2Ljk4NzYzNDExNTI5MzY5JX0u
cm93LWZsdWlkIC5vZmZzZXQxe21hcmdpbi1sZWZ0OjExLjExMTExMTExMTExMTExJTsqbWFyZ2luLWxl
ZnQ6MTEuMDA0NzI4MTMyMzg3NzA4JX0ucm93LWZsdWlkIC5vZmZzZXQxOmZpcnN0LWNoaWxke21hcmdp
bi1sZWZ0OjguNTQ3MDA4NTQ3MDA4NTQ3JTsqbWFyZ2luLWxlZnQ6OC40NDA2MjU1NjgyODUxNDIlfWlu
cHV0LHRleHRhcmVhLC51bmVkaXRhYmxlLWlucHV0e21hcmdpbi1sZWZ0OjB9LmNvbnRyb2xzLXJvdyBb
Y2xhc3MqPSJzcGFuIl0rW2NsYXNzKj0ic3BhbiJde21hcmdpbi1sZWZ0OjMwcHh9aW5wdXQuc3BhbjEy
LHRleHRhcmVhLnNwYW4xMiwudW5lZGl0YWJsZS1pbnB1dC5zcGFuMTJ7d2lkdGg6MTE1NnB4fWlucHV0
LnNwYW4xMSx0ZXh0YXJlYS5zcGFuMTEsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjExe3dpZHRoOjEwNTZw
eH1pbnB1dC5zcGFuMTAsdGV4dGFyZWEuc3BhbjEwLC51bmVkaXRhYmxlLWlucHV0LnNwYW4xMHt3aWR0
aDo5NTZweH1pbnB1dC5zcGFuOSx0ZXh0YXJlYS5zcGFuOSwudW5lZGl0YWJsZS1pbnB1dC5zcGFuOXt3
aWR0aDo4NTZweH1pbnB1dC5zcGFuOCx0ZXh0YXJlYS5zcGFuOCwudW5lZGl0YWJsZS1pbnB1dC5zcGFu
OHt3aWR0aDo3NTZweH1pbnB1dC5zcGFuNyx0ZXh0YXJlYS5zcGFuNywudW5lZGl0YWJsZS1pbnB1dC5z
cGFuN3t3aWR0aDo2NTZweH1pbnB1dC5zcGFuNix0ZXh0YXJlYS5zcGFuNiwudW5lZGl0YWJsZS1pbnB1
dC5zcGFuNnt3aWR0aDo1NTZweH1pbnB1dC5zcGFuNSx0ZXh0YXJlYS5zcGFuNSwudW5lZGl0YWJsZS1p
bnB1dC5zcGFuNXt3aWR0aDo0NTZweH1pbnB1dC5zcGFuNCx0ZXh0YXJlYS5zcGFuNCwudW5lZGl0YWJs
ZS1pbnB1dC5zcGFuNHt3aWR0aDozNTZweH1pbnB1dC5zcGFuMyx0ZXh0YXJlYS5zcGFuMywudW5lZGl0
YWJsZS1pbnB1dC5zcGFuM3t3aWR0aDoyNTZweH1pbnB1dC5zcGFuMix0ZXh0YXJlYS5zcGFuMiwudW5l
ZGl0YWJsZS1pbnB1dC5zcGFuMnt3aWR0aDoxNTZweH1pbnB1dC5zcGFuMSx0ZXh0YXJlYS5zcGFuMSwu
dW5lZGl0YWJsZS1pbnB1dC5zcGFuMXt3aWR0aDo1NnB4fS50aHVtYm5haWxze21hcmdpbi1sZWZ0Oi0z
MHB4fS50aHVtYm5haWxzPmxpe21hcmdpbi1sZWZ0OjMwcHh9LnJvdy1mbHVpZCAudGh1bWJuYWlsc3tt
YXJnaW4tbGVmdDowfX1AbWVkaWEobWluLXdpZHRoOjc2OHB4KSBhbmQgKG1heC13aWR0aDo5NzlweCl7
LnJvd3ttYXJnaW4tbGVmdDotMjBweDsqem9vbToxfS5yb3c6YmVmb3JlLC5yb3c6YWZ0ZXJ7ZGlzcGxh
eTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9LnJvdzphZnRlcntjbGVhcjpib3RofVtjbGFz
cyo9InNwYW4iXXtmbG9hdDpsZWZ0O21pbi1oZWlnaHQ6MXB4O21hcmdpbi1sZWZ0OjIwcHh9LmNvbnRh
aW5lciwubmF2YmFyLXN0YXRpYy10b3AgLmNvbnRhaW5lciwubmF2YmFyLWZpeGVkLXRvcCAuY29udGFp
bmVyLC5uYXZiYXItZml4ZWQtYm90dG9tIC5jb250YWluZXJ7d2lkdGg6NzI0cHh9LnNwYW4xMnt3aWR0
aDo3MjRweH0uc3BhbjExe3dpZHRoOjY2MnB4fS5zcGFuMTB7d2lkdGg6NjAwcHh9LnNwYW45e3dpZHRo
OjUzOHB4fS5zcGFuOHt3aWR0aDo0NzZweH0uc3Bhbjd7d2lkdGg6NDE0cHh9LnNwYW42e3dpZHRoOjM1
MnB4fS5zcGFuNXt3aWR0aDoyOTBweH0uc3BhbjR7d2lkdGg6MjI4cHh9LnNwYW4ze3dpZHRoOjE2NnB4
fS5zcGFuMnt3aWR0aDoxMDRweH0uc3BhbjF7d2lkdGg6NDJweH0ub2Zmc2V0MTJ7bWFyZ2luLWxlZnQ6
NzY0cHh9Lm9mZnNldDExe21hcmdpbi1sZWZ0OjcwMnB4fS5vZmZzZXQxMHttYXJnaW4tbGVmdDo2NDBw
eH0ub2Zmc2V0OXttYXJnaW4tbGVmdDo1NzhweH0ub2Zmc2V0OHttYXJnaW4tbGVmdDo1MTZweH0ub2Zm
c2V0N3ttYXJnaW4tbGVmdDo0NTRweH0ub2Zmc2V0NnttYXJnaW4tbGVmdDozOTJweH0ub2Zmc2V0NXtt
YXJnaW4tbGVmdDozMzBweH0ub2Zmc2V0NHttYXJnaW4tbGVmdDoyNjhweH0ub2Zmc2V0M3ttYXJnaW4t
bGVmdDoyMDZweH0ub2Zmc2V0MnttYXJnaW4tbGVmdDoxNDRweH0ub2Zmc2V0MXttYXJnaW4tbGVmdDo4
MnB4fS5yb3ctZmx1aWR7d2lkdGg6MTAwJTsqem9vbToxfS5yb3ctZmx1aWQ6YmVmb3JlLC5yb3ctZmx1
aWQ6YWZ0ZXJ7ZGlzcGxheTp0YWJsZTtsaW5lLWhlaWdodDowO2NvbnRlbnQ6IiJ9LnJvdy1mbHVpZDph
ZnRlcntjbGVhcjpib3RofS5yb3ctZmx1aWQgW2NsYXNzKj0ic3BhbiJde2Rpc3BsYXk6YmxvY2s7Zmxv
YXQ6bGVmdDt3aWR0aDoxMDAlO21pbi1oZWlnaHQ6MzBweDttYXJnaW4tbGVmdDoyLjc2MjQzMDkzOTIy
NjUxOTQlOyptYXJnaW4tbGVmdDoyLjcwOTIzOTQ0OTg2NDgxNyU7LXdlYmtpdC1ib3gtc2l6aW5nOmJv
cmRlci1ib3g7LW1vei1ib3gtc2l6aW5nOmJvcmRlci1ib3g7Ym94LXNpemluZzpib3JkZXItYm94fS5y
b3ctZmx1aWQgW2NsYXNzKj0ic3BhbiJdOmZpcnN0LWNoaWxke21hcmdpbi1sZWZ0OjB9LnJvdy1mbHVp
ZCAuY29udHJvbHMtcm93IFtjbGFzcyo9InNwYW4iXStbY2xhc3MqPSJzcGFuIl17bWFyZ2luLWxlZnQ6
Mi43NjI0MzA5MzkyMjY1MTk0JX0ucm93LWZsdWlkIC5zcGFuMTJ7d2lkdGg6MTAwJTsqd2lkdGg6OTku
OTQ2ODA4NTEwNjM4MjklfS5yb3ctZmx1aWQgLnNwYW4xMXt3aWR0aDo5MS40MzY0NjQwODgzOTc3OCU7
KndpZHRoOjkxLjM4MzI3MjU5OTAzNjA4JX0ucm93LWZsdWlkIC5zcGFuMTB7d2lkdGg6ODIuODcyOTI4
MTc2Nzk1NTglOyp3aWR0aDo4Mi44MTk3MzY2ODc0MzM4NyV9LnJvdy1mbHVpZCAuc3Bhbjl7d2lkdGg6
NzQuMzA5MzkyMjY1MTkzMzclOyp3aWR0aDo3NC4yNTYyMDA3NzU4MzE2NiV9LnJvdy1mbHVpZCAuc3Bh
bjh7d2lkdGg6NjUuNzQ1ODU2MzUzNTkxMTclOyp3aWR0aDo2NS42OTI2NjQ4NjQyMjk0NiV9LnJvdy1m
bHVpZCAuc3Bhbjd7d2lkdGg6NTcuMTgyMzIwNDQxOTg4OTUlOyp3aWR0aDo1Ny4xMjkxMjg5NTI2Mjcy
NSV9LnJvdy1mbHVpZCAuc3BhbjZ7d2lkdGg6NDguNjE4Nzg0NTMwMzg2NzQlOyp3aWR0aDo0OC41NjU1
OTMwNDEwMjUwNCV9LnJvdy1mbHVpZCAuc3BhbjV7d2lkdGg6NDAuMDU1MjQ4NjE4Nzg0NTMlOyp3aWR0
aDo0MC4wMDIwNTcxMjk0MjI4MyV9LnJvdy1mbHVpZCAuc3BhbjR7d2lkdGg6MzEuNDkxNzEyNzA3MTgy
MzIzJTsqd2lkdGg6MzEuNDM4NTIxMjE3ODIwNjIlfS5yb3ctZmx1aWQgLnNwYW4ze3dpZHRoOjIyLjky
ODE3Njc5NTU4MDExJTsqd2lkdGg6MjIuODc0OTg1MzA2MjE4NDElfS5yb3ctZmx1aWQgLnNwYW4ye3dp
ZHRoOjE0LjM2NDY0MDg4Mzk3NzklOyp3aWR0aDoxNC4zMTE0NDkzOTQ2MTYxOTklfS5yb3ctZmx1aWQg
LnNwYW4xe3dpZHRoOjUuODAxMTA0OTcyMzc1NjkxJTsqd2lkdGg6NS43NDc5MTM0ODMwMTM5ODglfS5y
b3ctZmx1aWQgLm9mZnNldDEye21hcmdpbi1sZWZ0OjEwNS41MjQ4NjE4Nzg0NTMwNCU7Km1hcmdpbi1s
ZWZ0OjEwNS40MTg0Nzg4OTk3Mjk2MiV9LnJvdy1mbHVpZCAub2Zmc2V0MTI6Zmlyc3QtY2hpbGR7bWFy
Z2luLWxlZnQ6MTAyLjc2MjQzMDkzOTIyNjUyJTsqbWFyZ2luLWxlZnQ6MTAyLjY1NjA0Nzk2MDUwMzEl
fS5yb3ctZmx1aWQgLm9mZnNldDExe21hcmdpbi1sZWZ0Ojk2Ljk2MTMyNTk2Njg1MDgyJTsqbWFyZ2lu
LWxlZnQ6OTYuODU0OTQyOTg4MTI3NCV9LnJvdy1mbHVpZCAub2Zmc2V0MTE6Zmlyc3QtY2hpbGR7bWFy
Z2luLWxlZnQ6OTQuMTk4ODk1MDI3NjI0MyU7Km1hcmdpbi1sZWZ0Ojk0LjA5MjUxMjA0ODkwMDg5JX0u
cm93LWZsdWlkIC5vZmZzZXQxMHttYXJnaW4tbGVmdDo4OC4zOTc3OTAwNTUyNDg2MiU7Km1hcmdpbi1s
ZWZ0Ojg4LjI5MTQwNzA3NjUyNTIlfS5yb3ctZmx1aWQgLm9mZnNldDEwOmZpcnN0LWNoaWxke21hcmdp
bi1sZWZ0Ojg1LjYzNTM1OTExNjAyMjElOyptYXJnaW4tbGVmdDo4NS41Mjg5NzYxMzcyOTg2OCV9LnJv
dy1mbHVpZCAub2Zmc2V0OXttYXJnaW4tbGVmdDo3OS44MzQyNTQxNDM2NDY0JTsqbWFyZ2luLWxlZnQ6
NzkuNzI3ODcxMTY0OTIyOTklfS5yb3ctZmx1aWQgLm9mZnNldDk6Zmlyc3QtY2hpbGR7bWFyZ2luLWxl
ZnQ6NzcuMDcxODIzMjA0NDE5ODklOyptYXJnaW4tbGVmdDo3Ni45NjU0NDAyMjU2OTY0NyV9LnJvdy1m
bHVpZCAub2Zmc2V0OHttYXJnaW4tbGVmdDo3MS4yNzA3MTgyMzIwNDQyJTsqbWFyZ2luLWxlZnQ6NzEu
MTY0MzM1MjUzMzIwNzklfS5yb3ctZmx1aWQgLm9mZnNldDg6Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6
NjguNTA4Mjg3MjkyODE3NjglOyptYXJnaW4tbGVmdDo2OC40MDE5MDQzMTQwOTQyNyV9LnJvdy1mbHVp
ZCAub2Zmc2V0N3ttYXJnaW4tbGVmdDo2Mi43MDcxODIzMjA0NDE5OSU7Km1hcmdpbi1sZWZ0OjYyLjYw
MDc5OTM0MTcxODU4NCV9LnJvdy1mbHVpZCAub2Zmc2V0NzpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo1
OS45NDQ3NTEzODEyMTU0NyU7Km1hcmdpbi1sZWZ0OjU5LjgzODM2ODQwMjQ5MjA2NSV9LnJvdy1mbHVp
ZCAub2Zmc2V0NnttYXJnaW4tbGVmdDo1NC4xNDM2NDY0MDg4Mzk3OCU7Km1hcmdpbi1sZWZ0OjU0LjAz
NzI2MzQzMDExNjM3NiV9LnJvdy1mbHVpZCAub2Zmc2V0NjpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo1
MS4zODEyMTU0Njk2MTMyNiU7Km1hcmdpbi1sZWZ0OjUxLjI3NDgzMjQ5MDg4OTg2JX0ucm93LWZsdWlk
IC5vZmZzZXQ1e21hcmdpbi1sZWZ0OjQ1LjU4MDExMDQ5NzIzNzU3JTsqbWFyZ2luLWxlZnQ6NDUuNDcz
NzI3NTE4NTE0MTclfS5yb3ctZmx1aWQgLm9mZnNldDU6Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6NDIu
ODE3Njc5NTU4MDExMDUlOyptYXJnaW4tbGVmdDo0Mi43MTEyOTY1NzkyODc2NSV9LnJvdy1mbHVpZCAu
b2Zmc2V0NHttYXJnaW4tbGVmdDozNy4wMTY1NzQ1ODU2MzUzNiU7Km1hcmdpbi1sZWZ0OjM2LjkxMDE5
MTYwNjkxMTk2JX0ucm93LWZsdWlkIC5vZmZzZXQ0OmZpcnN0LWNoaWxke21hcmdpbi1sZWZ0OjM0LjI1
NDE0MzY0NjQwODg0JTsqbWFyZ2luLWxlZnQ6MzQuMTQ3NzYwNjY3Njg1NDQlfS5yb3ctZmx1aWQgLm9m
ZnNldDN7bWFyZ2luLWxlZnQ6MjguNDUzMDM4Njc0MDMzMTUlOyptYXJnaW4tbGVmdDoyOC4zNDY2NTU2
OTUzMDk3NDYlfS5yb3ctZmx1aWQgLm9mZnNldDM6Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6MjUuNjkw
NjA3NzM0ODA2NjMlOyptYXJnaW4tbGVmdDoyNS41ODQyMjQ3NTYwODMyMjclfS5yb3ctZmx1aWQgLm9m
ZnNldDJ7bWFyZ2luLWxlZnQ6MTkuODg5NTAyNzYyNDMwOTQlOyptYXJnaW4tbGVmdDoxOS43ODMxMTk3
ODM3MDc1MzclfS5yb3ctZmx1aWQgLm9mZnNldDI6Zmlyc3QtY2hpbGR7bWFyZ2luLWxlZnQ6MTcuMTI3
MDcxODIzMjA0NDIlOyptYXJnaW4tbGVmdDoxNy4wMjA2ODg4NDQ0ODEwMiV9LnJvdy1mbHVpZCAub2Zm
c2V0MXttYXJnaW4tbGVmdDoxMS4zMjU5NjY4NTA4Mjg3MyU7Km1hcmdpbi1sZWZ0OjExLjIxOTU4Mzg3
MjEwNTMyNSV9LnJvdy1mbHVpZCAub2Zmc2V0MTpmaXJzdC1jaGlsZHttYXJnaW4tbGVmdDo4LjU2MzUz
NTkxMTYwMjIxJTsqbWFyZ2luLWxlZnQ6OC40NTcxNTI5MzI4Nzg4MDYlfWlucHV0LHRleHRhcmVhLC51
bmVkaXRhYmxlLWlucHV0e21hcmdpbi1sZWZ0OjB9LmNvbnRyb2xzLXJvdyBbY2xhc3MqPSJzcGFuIl0r
W2NsYXNzKj0ic3BhbiJde21hcmdpbi1sZWZ0OjIwcHh9aW5wdXQuc3BhbjEyLHRleHRhcmVhLnNwYW4x
MiwudW5lZGl0YWJsZS1pbnB1dC5zcGFuMTJ7d2lkdGg6NzEwcHh9aW5wdXQuc3BhbjExLHRleHRhcmVh
LnNwYW4xMSwudW5lZGl0YWJsZS1pbnB1dC5zcGFuMTF7d2lkdGg6NjQ4cHh9aW5wdXQuc3BhbjEwLHRl
eHRhcmVhLnNwYW4xMCwudW5lZGl0YWJsZS1pbnB1dC5zcGFuMTB7d2lkdGg6NTg2cHh9aW5wdXQuc3Bh
bjksdGV4dGFyZWEuc3BhbjksLnVuZWRpdGFibGUtaW5wdXQuc3Bhbjl7d2lkdGg6NTI0cHh9aW5wdXQu
c3BhbjgsdGV4dGFyZWEuc3BhbjgsLnVuZWRpdGFibGUtaW5wdXQuc3Bhbjh7d2lkdGg6NDYycHh9aW5w
dXQuc3BhbjcsdGV4dGFyZWEuc3BhbjcsLnVuZWRpdGFibGUtaW5wdXQuc3Bhbjd7d2lkdGg6NDAwcHh9
aW5wdXQuc3BhbjYsdGV4dGFyZWEuc3BhbjYsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjZ7d2lkdGg6MzM4
cHh9aW5wdXQuc3BhbjUsdGV4dGFyZWEuc3BhbjUsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjV7d2lkdGg6
Mjc2cHh9aW5wdXQuc3BhbjQsdGV4dGFyZWEuc3BhbjQsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjR7d2lk
dGg6MjE0cHh9aW5wdXQuc3BhbjMsdGV4dGFyZWEuc3BhbjMsLnVuZWRpdGFibGUtaW5wdXQuc3BhbjN7
d2lkdGg6MTUycHh9aW5wdXQuc3BhbjIsdGV4dGFyZWEuc3BhbjIsLnVuZWRpdGFibGUtaW5wdXQuc3Bh
bjJ7d2lkdGg6OTBweH1pbnB1dC5zcGFuMSx0ZXh0YXJlYS5zcGFuMSwudW5lZGl0YWJsZS1pbnB1dC5z
cGFuMXt3aWR0aDoyOHB4fX1AbWVkaWEobWF4LXdpZHRoOjc2N3B4KXtib2R5e3BhZGRpbmctcmlnaHQ6
MjBweDtwYWRkaW5nLWxlZnQ6MjBweH0ubmF2YmFyLWZpeGVkLXRvcCwubmF2YmFyLWZpeGVkLWJvdHRv
bSwubmF2YmFyLXN0YXRpYy10b3B7bWFyZ2luLXJpZ2h0Oi0yMHB4O21hcmdpbi1sZWZ0Oi0yMHB4fS5j
b250YWluZXItZmx1aWR7cGFkZGluZzowfS5kbC1ob3Jpem9udGFsIGR0e2Zsb2F0Om5vbmU7d2lkdGg6
YXV0bztjbGVhcjpub25lO3RleHQtYWxpZ246bGVmdH0uZGwtaG9yaXpvbnRhbCBkZHttYXJnaW4tbGVm
dDowfS5jb250YWluZXJ7d2lkdGg6YXV0b30ucm93LWZsdWlke3dpZHRoOjEwMCV9LnJvdywudGh1bWJu
YWlsc3ttYXJnaW4tbGVmdDowfS50aHVtYm5haWxzPmxpe2Zsb2F0Om5vbmU7bWFyZ2luLWxlZnQ6MH1b
Y2xhc3MqPSJzcGFuIl0sLnVuZWRpdGFibGUtaW5wdXRbY2xhc3MqPSJzcGFuIl0sLnJvdy1mbHVpZCBb
Y2xhc3MqPSJzcGFuIl17ZGlzcGxheTpibG9jaztmbG9hdDpub25lO3dpZHRoOjEwMCU7bWFyZ2luLWxl
ZnQ6MDstd2Via2l0LWJveC1zaXppbmc6Ym9yZGVyLWJveDstbW96LWJveC1zaXppbmc6Ym9yZGVyLWJv
eDtib3gtc2l6aW5nOmJvcmRlci1ib3h9LnNwYW4xMiwucm93LWZsdWlkIC5zcGFuMTJ7d2lkdGg6MTAw
JTstd2Via2l0LWJveC1zaXppbmc6Ym9yZGVyLWJveDstbW96LWJveC1zaXppbmc6Ym9yZGVyLWJveDti
b3gtc2l6aW5nOmJvcmRlci1ib3h9LnJvdy1mbHVpZCBbY2xhc3MqPSJvZmZzZXQiXTpmaXJzdC1jaGls
ZHttYXJnaW4tbGVmdDowfS5pbnB1dC1sYXJnZSwuaW5wdXQteGxhcmdlLC5pbnB1dC14eGxhcmdlLGlu
cHV0W2NsYXNzKj0ic3BhbiJdLHNlbGVjdFtjbGFzcyo9InNwYW4iXSx0ZXh0YXJlYVtjbGFzcyo9InNw
YW4iXSwudW5lZGl0YWJsZS1pbnB1dHtkaXNwbGF5OmJsb2NrO3dpZHRoOjEwMCU7bWluLWhlaWdodDoz
MHB4Oy13ZWJraXQtYm94LXNpemluZzpib3JkZXItYm94Oy1tb3otYm94LXNpemluZzpib3JkZXItYm94
O2JveC1zaXppbmc6Ym9yZGVyLWJveH0uaW5wdXQtcHJlcGVuZCBpbnB1dCwuaW5wdXQtYXBwZW5kIGlu
cHV0LC5pbnB1dC1wcmVwZW5kIGlucHV0W2NsYXNzKj0ic3BhbiJdLC5pbnB1dC1hcHBlbmQgaW5wdXRb
Y2xhc3MqPSJzcGFuIl17ZGlzcGxheTppbmxpbmUtYmxvY2s7d2lkdGg6YXV0b30uY29udHJvbHMtcm93
IFtjbGFzcyo9InNwYW4iXStbY2xhc3MqPSJzcGFuIl17bWFyZ2luLWxlZnQ6MH0ubW9kYWx7cG9zaXRp
b246Zml4ZWQ7dG9wOjIwcHg7cmlnaHQ6MjBweDtsZWZ0OjIwcHg7d2lkdGg6YXV0bzttYXJnaW46MH0u
bW9kYWwuZmFkZXt0b3A6LTEwMHB4fS5tb2RhbC5mYWRlLmlue3RvcDoyMHB4fX1AbWVkaWEobWF4LXdp
ZHRoOjQ4MHB4KXsubmF2LWNvbGxhcHNley13ZWJraXQtdHJhbnNmb3JtOnRyYW5zbGF0ZTNkKDAsMCww
KX0ucGFnZS1oZWFkZXIgaDEgc21hbGx7ZGlzcGxheTpibG9jaztsaW5lLWhlaWdodDoyMHB4fWlucHV0
W3R5cGU9ImNoZWNrYm94Il0saW5wdXRbdHlwZT0icmFkaW8iXXtib3JkZXI6MXB4IHNvbGlkICNjY2N9
LmZvcm0taG9yaXpvbnRhbCAuY29udHJvbC1sYWJlbHtmbG9hdDpub25lO3dpZHRoOmF1dG87cGFkZGlu
Zy10b3A6MDt0ZXh0LWFsaWduOmxlZnR9LmZvcm0taG9yaXpvbnRhbCAuY29udHJvbHN7bWFyZ2luLWxl
ZnQ6MH0uZm9ybS1ob3Jpem9udGFsIC5jb250cm9sLWxpc3R7cGFkZGluZy10b3A6MH0uZm9ybS1ob3Jp
em9udGFsIC5mb3JtLWFjdGlvbnN7cGFkZGluZy1yaWdodDoxMHB4O3BhZGRpbmctbGVmdDoxMHB4fS5t
ZWRpYSAucHVsbC1sZWZ0LC5tZWRpYSAucHVsbC1yaWdodHtkaXNwbGF5OmJsb2NrO2Zsb2F0Om5vbmU7
bWFyZ2luLWJvdHRvbToxMHB4fS5tZWRpYS1vYmplY3R7bWFyZ2luLXJpZ2h0OjA7bWFyZ2luLWxlZnQ6
MH0ubW9kYWx7dG9wOjEwcHg7cmlnaHQ6MTBweDtsZWZ0OjEwcHh9Lm1vZGFsLWhlYWRlciAuY2xvc2V7
cGFkZGluZzoxMHB4O21hcmdpbjotMTBweH0uY2Fyb3VzZWwtY2FwdGlvbntwb3NpdGlvbjpzdGF0aWN9
fUBtZWRpYShtYXgtd2lkdGg6OTc5cHgpe2JvZHl7cGFkZGluZy10b3A6MH0ubmF2YmFyLWZpeGVkLXRv
cCwubmF2YmFyLWZpeGVkLWJvdHRvbXtwb3NpdGlvbjpzdGF0aWN9Lm5hdmJhci1maXhlZC10b3B7bWFy
Z2luLWJvdHRvbToyMHB4fS5uYXZiYXItZml4ZWQtYm90dG9te21hcmdpbi10b3A6MjBweH0ubmF2YmFy
LWZpeGVkLXRvcCAubmF2YmFyLWlubmVyLC5uYXZiYXItZml4ZWQtYm90dG9tIC5uYXZiYXItaW5uZXJ7
cGFkZGluZzo1cHh9Lm5hdmJhciAuY29udGFpbmVye3dpZHRoOmF1dG87cGFkZGluZzowfS5uYXZiYXIg
LmJyYW5ke3BhZGRpbmctcmlnaHQ6MTBweDtwYWRkaW5nLWxlZnQ6MTBweDttYXJnaW46MCAwIDAgLTVw
eH0ubmF2LWNvbGxhcHNle2NsZWFyOmJvdGh9Lm5hdi1jb2xsYXBzZSAubmF2e2Zsb2F0Om5vbmU7bWFy
Z2luOjAgMCAxMHB4fS5uYXYtY29sbGFwc2UgLm5hdj5saXtmbG9hdDpub25lfS5uYXYtY29sbGFwc2Ug
Lm5hdj5saT5he21hcmdpbi1ib3R0b206MnB4fS5uYXYtY29sbGFwc2UgLm5hdj4uZGl2aWRlci12ZXJ0
aWNhbHtkaXNwbGF5Om5vbmV9Lm5hdi1jb2xsYXBzZSAubmF2IC5uYXYtaGVhZGVye2NvbG9yOiM3Nzc7
dGV4dC1zaGFkb3c6bm9uZX0ubmF2LWNvbGxhcHNlIC5uYXY+bGk+YSwubmF2LWNvbGxhcHNlIC5kcm9w
ZG93bi1tZW51IGF7cGFkZGluZzo5cHggMTVweDtmb250LXdlaWdodDpib2xkO2NvbG9yOiM3Nzc7LXdl
YmtpdC1ib3JkZXItcmFkaXVzOjNweDstbW96LWJvcmRlci1yYWRpdXM6M3B4O2JvcmRlci1yYWRpdXM6
M3B4fS5uYXYtY29sbGFwc2UgLmJ0bntwYWRkaW5nOjRweCAxMHB4IDRweDtmb250LXdlaWdodDpub3Jt
YWw7LXdlYmtpdC1ib3JkZXItcmFkaXVzOjRweDstbW96LWJvcmRlci1yYWRpdXM6NHB4O2JvcmRlci1y
YWRpdXM6NHB4fS5uYXYtY29sbGFwc2UgLmRyb3Bkb3duLW1lbnUgbGkrbGkgYXttYXJnaW4tYm90dG9t
OjJweH0ubmF2LWNvbGxhcHNlIC5uYXY+bGk+YTpob3ZlciwubmF2LWNvbGxhcHNlIC5uYXY+bGk+YTpm
b2N1cywubmF2LWNvbGxhcHNlIC5kcm9wZG93bi1tZW51IGE6aG92ZXIsLm5hdi1jb2xsYXBzZSAuZHJv
cGRvd24tbWVudSBhOmZvY3Vze2JhY2tncm91bmQtY29sb3I6I2YyZjJmMn0ubmF2YmFyLWludmVyc2Ug
Lm5hdi1jb2xsYXBzZSAubmF2PmxpPmEsLm5hdmJhci1pbnZlcnNlIC5uYXYtY29sbGFwc2UgLmRyb3Bk
b3duLW1lbnUgYXtjb2xvcjojOTk5fS5uYXZiYXItaW52ZXJzZSAubmF2LWNvbGxhcHNlIC5uYXY+bGk+
YTpob3ZlciwubmF2YmFyLWludmVyc2UgLm5hdi1jb2xsYXBzZSAubmF2PmxpPmE6Zm9jdXMsLm5hdmJh
ci1pbnZlcnNlIC5uYXYtY29sbGFwc2UgLmRyb3Bkb3duLW1lbnUgYTpob3ZlciwubmF2YmFyLWludmVy
c2UgLm5hdi1jb2xsYXBzZSAuZHJvcGRvd24tbWVudSBhOmZvY3Vze2JhY2tncm91bmQtY29sb3I6IzEx
MX0ubmF2LWNvbGxhcHNlLmluIC5idG4tZ3JvdXB7cGFkZGluZzowO21hcmdpbi10b3A6NXB4fS5uYXYt
Y29sbGFwc2UgLmRyb3Bkb3duLW1lbnV7cG9zaXRpb246c3RhdGljO3RvcDphdXRvO2xlZnQ6YXV0bztk
aXNwbGF5Om5vbmU7ZmxvYXQ6bm9uZTttYXgtd2lkdGg6bm9uZTtwYWRkaW5nOjA7bWFyZ2luOjAgMTVw
eDtiYWNrZ3JvdW5kLWNvbG9yOnRyYW5zcGFyZW50O2JvcmRlcjowOy13ZWJraXQtYm9yZGVyLXJhZGl1
czowOy1tb3otYm9yZGVyLXJhZGl1czowO2JvcmRlci1yYWRpdXM6MDstd2Via2l0LWJveC1zaGFkb3c6
bm9uZTstbW96LWJveC1zaGFkb3c6bm9uZTtib3gtc2hhZG93Om5vbmV9Lm5hdi1jb2xsYXBzZSAub3Bl
bj4uZHJvcGRvd24tbWVudXtkaXNwbGF5OmJsb2NrfS5uYXYtY29sbGFwc2UgLmRyb3Bkb3duLW1lbnU6
YmVmb3JlLC5uYXYtY29sbGFwc2UgLmRyb3Bkb3duLW1lbnU6YWZ0ZXJ7ZGlzcGxheTpub25lfS5uYXYt
Y29sbGFwc2UgLmRyb3Bkb3duLW1lbnUgLmRpdmlkZXJ7ZGlzcGxheTpub25lfS5uYXYtY29sbGFwc2Ug
Lm5hdj5saT4uZHJvcGRvd24tbWVudTpiZWZvcmUsLm5hdi1jb2xsYXBzZSAubmF2PmxpPi5kcm9wZG93
bi1tZW51OmFmdGVye2Rpc3BsYXk6bm9uZX0ubmF2LWNvbGxhcHNlIC5uYXZiYXItZm9ybSwubmF2LWNv
bGxhcHNlIC5uYXZiYXItc2VhcmNoe2Zsb2F0Om5vbmU7cGFkZGluZzoxMHB4IDE1cHg7bWFyZ2luOjEw
cHggMDtib3JkZXItdG9wOjFweCBzb2xpZCAjZjJmMmYyO2JvcmRlci1ib3R0b206MXB4IHNvbGlkICNm
MmYyZjI7LXdlYmtpdC1ib3gtc2hhZG93Omluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjEp
LDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjEpOy1tb3otYm94LXNoYWRvdzppbnNldCAwIDFweCAw
IHJnYmEoMjU1LDI1NSwyNTUsMC4xKSwwIDFweCAwIHJnYmEoMjU1LDI1NSwyNTUsMC4xKTtib3gtc2hh
ZG93Omluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwwLjEpLDAgMXB4IDAgcmdiYSgyNTUsMjU1
LDI1NSwwLjEpfS5uYXZiYXItaW52ZXJzZSAubmF2LWNvbGxhcHNlIC5uYXZiYXItZm9ybSwubmF2YmFy
LWludmVyc2UgLm5hdi1jb2xsYXBzZSAubmF2YmFyLXNlYXJjaHtib3JkZXItdG9wLWNvbG9yOiMxMTE7
Ym9yZGVyLWJvdHRvbS1jb2xvcjojMTExfS5uYXZiYXIgLm5hdi1jb2xsYXBzZSAubmF2LnB1bGwtcmln
aHR7ZmxvYXQ6bm9uZTttYXJnaW4tbGVmdDowfS5uYXYtY29sbGFwc2UsLm5hdi1jb2xsYXBzZS5jb2xs
YXBzZXtoZWlnaHQ6MDtvdmVyZmxvdzpoaWRkZW59Lm5hdmJhciAuYnRuLW5hdmJhcntkaXNwbGF5OmJs
b2NrfS5uYXZiYXItc3RhdGljIC5uYXZiYXItaW5uZXJ7cGFkZGluZy1yaWdodDoxMHB4O3BhZGRpbmct
bGVmdDoxMHB4fX1AbWVkaWEobWluLXdpZHRoOjk4MHB4KXsubmF2LWNvbGxhcHNlLmNvbGxhcHNle2hl
aWdodDphdXRvIWltcG9ydGFudDtvdmVyZmxvdzp2aXNpYmxlIWltcG9ydGFudH19Cg==
__END__

=head1 NAME

Mojolicious::Command::generate::bootstrap_app - Generates a basic application with simple DBIC-based authentication featuring Twitter Bootstrap.

=head1 VERSION

Version 0.02

=head1 SYNOPSIS

This command generate an application with a DBIx::Class model and a simple authentication controller.

To generate an app run:

    mojo generate bootstrap_app My::Bootstrap::App

This will create the directory structure with a default YAML config and basic testing.

    cd my_bootstrap_app

To get database version and migration management you should install DBIx::Class::Migration.

If installed you can use script/migration as a thin wrapper around dbic-migration setting lib and the correct database already.
Running:

    script/migrate prepare
    script/migrate install
    script/migrate populate

Will initialize the database according to the config.yml with the data from share/fixtures. So edit those to customize the default user.
If you do not have and do not want DBIx::Class::Migrate you can initialize the database with:

    script/migrate --init

Now run the test to check if everything went right.

    script/my_bootstrap_app test

=head1 AUTHOR

Matthias Krull, C<< <m.krull at uninets.eu> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-mojolicious-command-generate-bootstrap_app at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Mojolicious-Command-generate-bootstrap_app>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mojolicious::Command::generate::bootstrap_app


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Mojolicious-Command-generate-bootstrap_app>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Mojolicious-Command-generate-bootstrap_app>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Mojolicious-Command-generate-bootstrap_app>

=item * Search CPAN

L<http://search.cpan.org/dist/Mojolicious-Command-generate-bootstrap_app/>

=item * Repository

L<https://github.com/uninets/Mojolicious-Command-generate-bootstrap_app/>

=back


=head1 LICENSE AND COPYRIGHT

The Twitter Bootstrap parts:

L<http://www.apache.org/licenses/LICENSE-2.0>

L<https://github.com/twitter/bootstrap/wiki/License>

The generator:

Copyright 2013 Matthias Krull.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

