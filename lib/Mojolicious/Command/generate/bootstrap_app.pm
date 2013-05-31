package Mojolicious::Command::generate::bootstrap_app;

use strict;
use warnings;
use Mojo::Base 'Mojolicious::Command';
use Mojo::Util qw(class_to_path class_to_file);
use String::Random qw(random_string);
use MIME::Base64;

our $VERSION = 0.06;

has description => "Generate Mojolicious application directory structure including Twitter Bootstrap assets and DBIC authentication.\n";
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
    $self->render_base64_to_rel_file('jquery', "$name/public/bootstrap/js/jquery.min.js");

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
    my $app_controller     = class_to_path $controller_namespace;
    my $example_controller = class_to_path "${controller_namespace}::Example";
    my $auth_controller    = class_to_path "${controller_namespace}::Auth";
    my $users_controller   = class_to_path "${controller_namespace}::Users";
    $self->render_to_rel_file('app_controller', "$name/lib/$app_controller", ${controller_namespace});
    $self->render_to_rel_file('example_controller', "$name/lib/$example_controller", ${controller_namespace}, "Example");
    $self->render_to_rel_file('auth_controller', "$name/lib/$auth_controller", ${controller_namespace}, "Auth");
    $self->render_to_rel_file('users_controller', "$name/lib/$users_controller", ${controller_namespace}, "Users");

    # models
    my $schema = class_to_path $model_namespace;
    $self->render_to_rel_file('schema', "$name/lib/$schema", $model_namespace);
    my $usermodel = class_to_path "${model_namespace}::Result::User";
    $self->render_to_rel_file('users_model', "$name/lib/$usermodel", $model_namespace);

    # db_deploy_script
    $self->render_to_rel_file('migrate', "$name/script/migrate", $model_namespace, $model_name);
    $self->chmod_file("$name/script/migrate", 0744);

    # fixtures
    for my $mode (qw(production development testing)) {
        $self->render_to_rel_file('fixture', "$name/share/$mode/fixtures/1/all_tables/users/1.fix");
        $self->render_to_rel_file('fixture_config', "$name/share/$mode/fixtures/1/conf/all_tables.json");
    };

    # tests
    $self->render_to_rel_file('test', "$name/t/basic.t", $class );

    # config
    $self->render_to_rel_file('config', "$name/config.yml", $model_name);

    # db (to play with DBIx::Class::Migration nicely
    $self->create_rel_dir("$name/db");

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
    $self->secret($self->config->{$self->app->mode}->{session_secret});
    # set loglevel
    $self->app->log->level($self->config->{$self->app->mode}->{loglevel});

    # Documentation browser under "/perldoc"
    $self->plugin('PODRenderer');

    # database connection prefork save with DBIx::Connector
    my $connector = DBIx::Connector->new(build_dsn($self->config->{$self->app->mode}->{database}), $self->config->{$self->app->mode}->{database}->{dbuser}, $self->config->{$self->app->mode}->{database}->{dbpass});
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
use YAML;
use <%= $class %>;

my %config = (
    production => {
        database => {
            driver => 'SQLite',
            dbname => 'share/<%= $name %>.db',
            dbuser => '',
            dbpass => '',
            dbhost => '',
            dbport => 0,
        },
    },
    development => {
        database => {
            driver => 'SQLite',
            dbname => 'share/<%= $name %>_dev.db',
            dbuser => '',
            dbpass => '',
            dbhost => '',
            dbport => 0,
        },
    },
    testing => {
        database => {
            driver => 'SQLite',
            dbname => 'share/<%= $name %>_test.db',
            dbuser => '',
            dbpass => '',
            dbhost => '',
            dbport => 0,
        },
    },
);

my $config_file = 'config.yml';
my $conf = YAML::LoadFile($config_file);

@config{ keys %$conf } = values %$conf;

my $mode = $ENV{MOJO_MODE} || 'development';
die "No configuration found for run mode '$mode'" unless $config{$mode};

my $init = 0;
my $result = GetOptions(
    'init' => \$init,
);

my $dsn_head = "dbi:$config{$mode}{database}{driver}:dbname=$config{$mode}{database}{dbname};";
my $dsn_host = $config{$mode}{database}{dbhost} ? "host=$config{$mode}{database}{dbhost};" : '';
my $dsn_port = $config{$mode}{database}{dbport} ? "port=$config{$mode}{database}{dbport};" : '';

my $dsn = $dsn_head . $dsn_host . $dsn_port;

$ENV{DBIC_MIGRATION_SCHEMA_CLASS} = '<%= $class %>';
$ENV{DBIC_MIGRATION_TARGET_DIR}   = "share/$mode";

eval {
    require DBIx::Class::Migration;
    DBIx::Class::Migration->import();
};

if ($@ || $init) {
    say "Run this script after installing DBIx::Class::Migration for database version management.";
    unless ($init) {
        say "To initialize the database anyway run ${0} --init";
        exit 1;
    }

    require <%= $class %>;
    <%= $class %>->import();
    my $schema = <%= $class %>->connect(
        $dsn,
        $config{$mode}{database}{dbuser},
        $config{$mode}{database}{dbpass}
    );
    $schema->deploy;
    my $admin = do "share/$mode/fixtures/1/all_tables/users/1.fix";
    $schema->resultset('User')->create($admin);
}
else {
    unshift @ARGV, (
        '--dsn', $dsn,
        '--username', $config{$mode}{database}{dbuser},
        '--password', $config{$mode}{database}{dbpass},
    );
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

@@ app_controller
% my $controller = shift;
package <%= $controller %>;
use Mojo::Base 'Mojolicious::Controller';

# application wide controller code goes here

1;


@@ auth_controller
% my $controller = shift;
% my $class = shift;
package <%= $controller . '::' . $class %>;
use Mojo::Base '<%= $controller %>';
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
% my $controller = shift;
% my $class = shift;
package <%= $controller . '::' . $class %>;
use Mojo::Base '<%= $controller %>';

# This action will render a template
sub welcome {
    my $self = shift;

    $self->render();
}

1;

@@ users_controller
% my $controller = shift;
% my $class = shift;
package <%= $controller . '::' . $class %>;
use Mojo::Base '<%= $controller %>';

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
%% title 'Add User';
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
%% title 'Edit User';
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
        %%= javascript '/bootstrap/js/jquery.min.js'
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
$t->post_ok('/authenticate' => form => { login => 'admin', password => 'password' })
    ->status_is(200)
    ->get_ok('/')->status_is(200)->content_like(qr/Mojolicious/i);

done_testing();

@@ config
% my $db_name = shift;
production:
  database:
    driver: "SQLite"
    dbname: "share/<%= $db_name %>.db"
    dbuser: ""
    dbhost: ""
    dbpass: ""
    dbport: 0

  loglevel: "info"
  hypnotoad:
    listen:
      - "http://*:8080"

development:
  database:
    driver: "SQLite"
    dbname: "share/<%= $db_name %>_dev.db"
    dbuser: ""
    dbhost: ""
    dbpass: ""
    dbport: 0

  loglevel: "debug"

testing:
  database:
    driver: "SQLite"
    dbname: "share/<%= $db_name %>_test.db"
    dbuser: ""
    dbhost: ""
    dbpass: ""
    dbport: 0

  loglevel: "debug"

@@ jquery
LyohIGpRdWVyeSB2Mi4wLjEgfCAoYykgMjAwNSwgMjAxMyBqUXVlcnkgRm91bmRhdGlvbiwgSW5j
LiB8IGpxdWVyeS5vcmcvbGljZW5zZQovL0Agc291cmNlTWFwcGluZ1VSTD1qcXVlcnktMi4wLjEu
bWluLm1hcAoqLwooZnVuY3Rpb24oZSx1bmRlZmluZWQpe3ZhciB0LG4scj10eXBlb2YgdW5kZWZp
bmVkLGk9ZS5sb2NhdGlvbixvPWUuZG9jdW1lbnQscz1vLmRvY3VtZW50RWxlbWVudCxhPWUualF1
ZXJ5LHU9ZS4kLGw9e30sYz1bXSxmPSIyLjAuMSIscD1jLmNvbmNhdCxoPWMucHVzaCxkPWMuc2xp
Y2UsZz1jLmluZGV4T2YsbT1sLnRvU3RyaW5nLHk9bC5oYXNPd25Qcm9wZXJ0eSx2PWYudHJpbSx4
PWZ1bmN0aW9uKGUsbil7cmV0dXJuIG5ldyB4LmZuLmluaXQoZSxuLHQpfSxiPS9bKy1dPyg/Olxk
KlwufClcZCsoPzpbZUVdWystXT9cZCt8KS8uc291cmNlLHc9L1xTKy9nLFQ9L14oPzpccyooPFtc
d1xXXSs+KVtePl0qfCMoW1x3LV0qKSkkLyxDPS9ePChcdyspXHMqXC8/Pig/OjxcL1wxPnwpJC8s
az0vXi1tcy0vLE49Ly0oW1xkYS16XSkvZ2ksRT1mdW5jdGlvbihlLHQpe3JldHVybiB0LnRvVXBw
ZXJDYXNlKCl9LFM9ZnVuY3Rpb24oKXtvLnJlbW92ZUV2ZW50TGlzdGVuZXIoIkRPTUNvbnRlbnRM
b2FkZWQiLFMsITEpLGUucmVtb3ZlRXZlbnRMaXN0ZW5lcigibG9hZCIsUywhMSkseC5yZWFkeSgp
fTt4LmZuPXgucHJvdG90eXBlPXtqcXVlcnk6Zixjb25zdHJ1Y3Rvcjp4LGluaXQ6ZnVuY3Rpb24o
ZSx0LG4pe3ZhciByLGk7aWYoIWUpcmV0dXJuIHRoaXM7aWYoInN0cmluZyI9PXR5cGVvZiBlKXtp
ZihyPSI8Ij09PWUuY2hhckF0KDApJiYiPiI9PT1lLmNoYXJBdChlLmxlbmd0aC0xKSYmZS5sZW5n
dGg+PTM/W251bGwsZSxudWxsXTpULmV4ZWMoZSksIXJ8fCFyWzFdJiZ0KXJldHVybiF0fHx0Lmpx
dWVyeT8odHx8bikuZmluZChlKTp0aGlzLmNvbnN0cnVjdG9yKHQpLmZpbmQoZSk7aWYoclsxXSl7
aWYodD10IGluc3RhbmNlb2YgeD90WzBdOnQseC5tZXJnZSh0aGlzLHgucGFyc2VIVE1MKHJbMV0s
dCYmdC5ub2RlVHlwZT90Lm93bmVyRG9jdW1lbnR8fHQ6bywhMCkpLEMudGVzdChyWzFdKSYmeC5p
c1BsYWluT2JqZWN0KHQpKWZvcihyIGluIHQpeC5pc0Z1bmN0aW9uKHRoaXNbcl0pP3RoaXNbcl0o
dFtyXSk6dGhpcy5hdHRyKHIsdFtyXSk7cmV0dXJuIHRoaXN9cmV0dXJuIGk9by5nZXRFbGVtZW50
QnlJZChyWzJdKSxpJiZpLnBhcmVudE5vZGUmJih0aGlzLmxlbmd0aD0xLHRoaXNbMF09aSksdGhp
cy5jb250ZXh0PW8sdGhpcy5zZWxlY3Rvcj1lLHRoaXN9cmV0dXJuIGUubm9kZVR5cGU/KHRoaXMu
Y29udGV4dD10aGlzWzBdPWUsdGhpcy5sZW5ndGg9MSx0aGlzKTp4LmlzRnVuY3Rpb24oZSk/bi5y
ZWFkeShlKTooZS5zZWxlY3RvciE9PXVuZGVmaW5lZCYmKHRoaXMuc2VsZWN0b3I9ZS5zZWxlY3Rv
cix0aGlzLmNvbnRleHQ9ZS5jb250ZXh0KSx4Lm1ha2VBcnJheShlLHRoaXMpKX0sc2VsZWN0b3I6
IiIsbGVuZ3RoOjAsdG9BcnJheTpmdW5jdGlvbigpe3JldHVybiBkLmNhbGwodGhpcyl9LGdldDpm
dW5jdGlvbihlKXtyZXR1cm4gbnVsbD09ZT90aGlzLnRvQXJyYXkoKTowPmU/dGhpc1t0aGlzLmxl
bmd0aCtlXTp0aGlzW2VdfSxwdXNoU3RhY2s6ZnVuY3Rpb24oZSl7dmFyIHQ9eC5tZXJnZSh0aGlz
LmNvbnN0cnVjdG9yKCksZSk7cmV0dXJuIHQucHJldk9iamVjdD10aGlzLHQuY29udGV4dD10aGlz
LmNvbnRleHQsdH0sZWFjaDpmdW5jdGlvbihlLHQpe3JldHVybiB4LmVhY2godGhpcyxlLHQpfSxy
ZWFkeTpmdW5jdGlvbihlKXtyZXR1cm4geC5yZWFkeS5wcm9taXNlKCkuZG9uZShlKSx0aGlzfSxz
bGljZTpmdW5jdGlvbigpe3JldHVybiB0aGlzLnB1c2hTdGFjayhkLmFwcGx5KHRoaXMsYXJndW1l
bnRzKSl9LGZpcnN0OmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMuZXEoMCl9LGxhc3Q6ZnVuY3Rpb24o
KXtyZXR1cm4gdGhpcy5lcSgtMSl9LGVxOmZ1bmN0aW9uKGUpe3ZhciB0PXRoaXMubGVuZ3RoLG49
K2UrKDA+ZT90OjApO3JldHVybiB0aGlzLnB1c2hTdGFjayhuPj0wJiZ0Pm4/W3RoaXNbbl1dOltd
KX0sbWFwOmZ1bmN0aW9uKGUpe3JldHVybiB0aGlzLnB1c2hTdGFjayh4Lm1hcCh0aGlzLGZ1bmN0
aW9uKHQsbil7cmV0dXJuIGUuY2FsbCh0LG4sdCl9KSl9LGVuZDpmdW5jdGlvbigpe3JldHVybiB0
aGlzLnByZXZPYmplY3R8fHRoaXMuY29uc3RydWN0b3IobnVsbCl9LHB1c2g6aCxzb3J0OltdLnNv
cnQsc3BsaWNlOltdLnNwbGljZX0seC5mbi5pbml0LnByb3RvdHlwZT14LmZuLHguZXh0ZW5kPXgu
Zm4uZXh0ZW5kPWZ1bmN0aW9uKCl7dmFyIGUsdCxuLHIsaSxvLHM9YXJndW1lbnRzWzBdfHx7fSxh
PTEsdT1hcmd1bWVudHMubGVuZ3RoLGw9ITE7Zm9yKCJib29sZWFuIj09dHlwZW9mIHMmJihsPXMs
cz1hcmd1bWVudHNbMV18fHt9LGE9MiksIm9iamVjdCI9PXR5cGVvZiBzfHx4LmlzRnVuY3Rpb24o
cyl8fChzPXt9KSx1PT09YSYmKHM9dGhpcywtLWEpO3U+YTthKyspaWYobnVsbCE9KGU9YXJndW1l
bnRzW2FdKSlmb3IodCBpbiBlKW49c1t0XSxyPWVbdF0scyE9PXImJihsJiZyJiYoeC5pc1BsYWlu
T2JqZWN0KHIpfHwoaT14LmlzQXJyYXkocikpKT8oaT8oaT0hMSxvPW4mJnguaXNBcnJheShuKT9u
OltdKTpvPW4mJnguaXNQbGFpbk9iamVjdChuKT9uOnt9LHNbdF09eC5leHRlbmQobCxvLHIpKTpy
IT09dW5kZWZpbmVkJiYoc1t0XT1yKSk7cmV0dXJuIHN9LHguZXh0ZW5kKHtleHBhbmRvOiJqUXVl
cnkiKyhmK01hdGgucmFuZG9tKCkpLnJlcGxhY2UoL1xEL2csIiIpLG5vQ29uZmxpY3Q6ZnVuY3Rp
b24odCl7cmV0dXJuIGUuJD09PXgmJihlLiQ9dSksdCYmZS5qUXVlcnk9PT14JiYoZS5qUXVlcnk9
YSkseH0saXNSZWFkeTohMSxyZWFkeVdhaXQ6MSxob2xkUmVhZHk6ZnVuY3Rpb24oZSl7ZT94LnJl
YWR5V2FpdCsrOngucmVhZHkoITApfSxyZWFkeTpmdW5jdGlvbihlKXsoZT09PSEwPy0teC5yZWFk
eVdhaXQ6eC5pc1JlYWR5KXx8KHguaXNSZWFkeT0hMCxlIT09ITAmJi0teC5yZWFkeVdhaXQ+MHx8
KG4ucmVzb2x2ZVdpdGgobyxbeF0pLHguZm4udHJpZ2dlciYmeChvKS50cmlnZ2VyKCJyZWFkeSIp
Lm9mZigicmVhZHkiKSkpfSxpc0Z1bmN0aW9uOmZ1bmN0aW9uKGUpe3JldHVybiJmdW5jdGlvbiI9
PT14LnR5cGUoZSl9LGlzQXJyYXk6QXJyYXkuaXNBcnJheSxpc1dpbmRvdzpmdW5jdGlvbihlKXty
ZXR1cm4gbnVsbCE9ZSYmZT09PWUud2luZG93fSxpc051bWVyaWM6ZnVuY3Rpb24oZSl7cmV0dXJu
IWlzTmFOKHBhcnNlRmxvYXQoZSkpJiZpc0Zpbml0ZShlKX0sdHlwZTpmdW5jdGlvbihlKXtyZXR1
cm4gbnVsbD09ZT9lKyIiOiJvYmplY3QiPT10eXBlb2YgZXx8ImZ1bmN0aW9uIj09dHlwZW9mIGU/
bFttLmNhbGwoZSldfHwib2JqZWN0Ijp0eXBlb2YgZX0saXNQbGFpbk9iamVjdDpmdW5jdGlvbihl
KXtpZigib2JqZWN0IiE9PXgudHlwZShlKXx8ZS5ub2RlVHlwZXx8eC5pc1dpbmRvdyhlKSlyZXR1
cm4hMTt0cnl7aWYoZS5jb25zdHJ1Y3RvciYmIXkuY2FsbChlLmNvbnN0cnVjdG9yLnByb3RvdHlw
ZSwiaXNQcm90b3R5cGVPZiIpKXJldHVybiExfWNhdGNoKHQpe3JldHVybiExfXJldHVybiEwfSxp
c0VtcHR5T2JqZWN0OmZ1bmN0aW9uKGUpe3ZhciB0O2Zvcih0IGluIGUpcmV0dXJuITE7cmV0dXJu
ITB9LGVycm9yOmZ1bmN0aW9uKGUpe3Rocm93IEVycm9yKGUpfSxwYXJzZUhUTUw6ZnVuY3Rpb24o
ZSx0LG4pe2lmKCFlfHwic3RyaW5nIiE9dHlwZW9mIGUpcmV0dXJuIG51bGw7ImJvb2xlYW4iPT10
eXBlb2YgdCYmKG49dCx0PSExKSx0PXR8fG87dmFyIHI9Qy5leGVjKGUpLGk9IW4mJltdO3JldHVy
biByP1t0LmNyZWF0ZUVsZW1lbnQoclsxXSldOihyPXguYnVpbGRGcmFnbWVudChbZV0sdCxpKSxp
JiZ4KGkpLnJlbW92ZSgpLHgubWVyZ2UoW10sci5jaGlsZE5vZGVzKSl9LHBhcnNlSlNPTjpKU09O
LnBhcnNlLHBhcnNlWE1MOmZ1bmN0aW9uKGUpe3ZhciB0LG47aWYoIWV8fCJzdHJpbmciIT10eXBl
b2YgZSlyZXR1cm4gbnVsbDt0cnl7bj1uZXcgRE9NUGFyc2VyLHQ9bi5wYXJzZUZyb21TdHJpbmco
ZSwidGV4dC94bWwiKX1jYXRjaChyKXt0PXVuZGVmaW5lZH1yZXR1cm4oIXR8fHQuZ2V0RWxlbWVu
dHNCeVRhZ05hbWUoInBhcnNlcmVycm9yIikubGVuZ3RoKSYmeC5lcnJvcigiSW52YWxpZCBYTUw6
ICIrZSksdH0sbm9vcDpmdW5jdGlvbigpe30sZ2xvYmFsRXZhbDpmdW5jdGlvbihlKXt2YXIgdCxu
PWV2YWw7ZT14LnRyaW0oZSksZSYmKDE9PT1lLmluZGV4T2YoInVzZSBzdHJpY3QiKT8odD1vLmNy
ZWF0ZUVsZW1lbnQoInNjcmlwdCIpLHQudGV4dD1lLG8uaGVhZC5hcHBlbmRDaGlsZCh0KS5wYXJl
bnROb2RlLnJlbW92ZUNoaWxkKHQpKTpuKGUpKX0sY2FtZWxDYXNlOmZ1bmN0aW9uKGUpe3JldHVy
biBlLnJlcGxhY2UoaywibXMtIikucmVwbGFjZShOLEUpfSxub2RlTmFtZTpmdW5jdGlvbihlLHQp
e3JldHVybiBlLm5vZGVOYW1lJiZlLm5vZGVOYW1lLnRvTG93ZXJDYXNlKCk9PT10LnRvTG93ZXJD
YXNlKCl9LGVhY2g6ZnVuY3Rpb24oZSx0LG4pe3ZhciByLGk9MCxvPWUubGVuZ3RoLHM9aihlKTtp
ZihuKXtpZihzKXtmb3IoO28+aTtpKyspaWYocj10LmFwcGx5KGVbaV0sbikscj09PSExKWJyZWFr
fWVsc2UgZm9yKGkgaW4gZSlpZihyPXQuYXBwbHkoZVtpXSxuKSxyPT09ITEpYnJlYWt9ZWxzZSBp
ZihzKXtmb3IoO28+aTtpKyspaWYocj10LmNhbGwoZVtpXSxpLGVbaV0pLHI9PT0hMSlicmVha31l
bHNlIGZvcihpIGluIGUpaWYocj10LmNhbGwoZVtpXSxpLGVbaV0pLHI9PT0hMSlicmVhaztyZXR1
cm4gZX0sdHJpbTpmdW5jdGlvbihlKXtyZXR1cm4gbnVsbD09ZT8iIjp2LmNhbGwoZSl9LG1ha2VB
cnJheTpmdW5jdGlvbihlLHQpe3ZhciBuPXR8fFtdO3JldHVybiBudWxsIT1lJiYoaihPYmplY3Qo
ZSkpP3gubWVyZ2Uobiwic3RyaW5nIj09dHlwZW9mIGU/W2VdOmUpOmguY2FsbChuLGUpKSxufSxp
bkFycmF5OmZ1bmN0aW9uKGUsdCxuKXtyZXR1cm4gbnVsbD09dD8tMTpnLmNhbGwodCxlLG4pfSxt
ZXJnZTpmdW5jdGlvbihlLHQpe3ZhciBuPXQubGVuZ3RoLHI9ZS5sZW5ndGgsaT0wO2lmKCJudW1i
ZXIiPT10eXBlb2Ygbilmb3IoO24+aTtpKyspZVtyKytdPXRbaV07ZWxzZSB3aGlsZSh0W2ldIT09
dW5kZWZpbmVkKWVbcisrXT10W2krK107cmV0dXJuIGUubGVuZ3RoPXIsZX0sZ3JlcDpmdW5jdGlv
bihlLHQsbil7dmFyIHIsaT1bXSxvPTAscz1lLmxlbmd0aDtmb3Iobj0hIW47cz5vO28rKylyPSEh
dChlW29dLG8pLG4hPT1yJiZpLnB1c2goZVtvXSk7cmV0dXJuIGl9LG1hcDpmdW5jdGlvbihlLHQs
bil7dmFyIHIsaT0wLG89ZS5sZW5ndGgscz1qKGUpLGE9W107aWYocylmb3IoO28+aTtpKyspcj10
KGVbaV0saSxuKSxudWxsIT1yJiYoYVthLmxlbmd0aF09cik7ZWxzZSBmb3IoaSBpbiBlKXI9dChl
W2ldLGksbiksbnVsbCE9ciYmKGFbYS5sZW5ndGhdPXIpO3JldHVybiBwLmFwcGx5KFtdLGEpfSxn
dWlkOjEscHJveHk6ZnVuY3Rpb24oZSx0KXt2YXIgbixyLGk7cmV0dXJuInN0cmluZyI9PXR5cGVv
ZiB0JiYobj1lW3RdLHQ9ZSxlPW4pLHguaXNGdW5jdGlvbihlKT8ocj1kLmNhbGwoYXJndW1lbnRz
LDIpLGk9ZnVuY3Rpb24oKXtyZXR1cm4gZS5hcHBseSh0fHx0aGlzLHIuY29uY2F0KGQuY2FsbChh
cmd1bWVudHMpKSl9LGkuZ3VpZD1lLmd1aWQ9ZS5ndWlkfHx4Lmd1aWQrKyxpKTp1bmRlZmluZWR9
LGFjY2VzczpmdW5jdGlvbihlLHQsbixyLGksbyxzKXt2YXIgYT0wLHU9ZS5sZW5ndGgsbD1udWxs
PT1uO2lmKCJvYmplY3QiPT09eC50eXBlKG4pKXtpPSEwO2ZvcihhIGluIG4peC5hY2Nlc3MoZSx0
LGEsblthXSwhMCxvLHMpfWVsc2UgaWYociE9PXVuZGVmaW5lZCYmKGk9ITAseC5pc0Z1bmN0aW9u
KHIpfHwocz0hMCksbCYmKHM/KHQuY2FsbChlLHIpLHQ9bnVsbCk6KGw9dCx0PWZ1bmN0aW9uKGUs
dCxuKXtyZXR1cm4gbC5jYWxsKHgoZSksbil9KSksdCkpZm9yKDt1PmE7YSsrKXQoZVthXSxuLHM/
cjpyLmNhbGwoZVthXSxhLHQoZVthXSxuKSkpO3JldHVybiBpP2U6bD90LmNhbGwoZSk6dT90KGVb
MF0sbik6b30sbm93OkRhdGUubm93LHN3YXA6ZnVuY3Rpb24oZSx0LG4scil7dmFyIGksbyxzPXt9
O2ZvcihvIGluIHQpc1tvXT1lLnN0eWxlW29dLGUuc3R5bGVbb109dFtvXTtpPW4uYXBwbHkoZSxy
fHxbXSk7Zm9yKG8gaW4gdCllLnN0eWxlW29dPXNbb107cmV0dXJuIGl9fSkseC5yZWFkeS5wcm9t
aXNlPWZ1bmN0aW9uKHQpe3JldHVybiBufHwobj14LkRlZmVycmVkKCksImNvbXBsZXRlIj09PW8u
cmVhZHlTdGF0ZT9zZXRUaW1lb3V0KHgucmVhZHkpOihvLmFkZEV2ZW50TGlzdGVuZXIoIkRPTUNv
bnRlbnRMb2FkZWQiLFMsITEpLGUuYWRkRXZlbnRMaXN0ZW5lcigibG9hZCIsUywhMSkpKSxuLnBy
b21pc2UodCl9LHguZWFjaCgiQm9vbGVhbiBOdW1iZXIgU3RyaW5nIEZ1bmN0aW9uIEFycmF5IERh
dGUgUmVnRXhwIE9iamVjdCBFcnJvciIuc3BsaXQoIiAiKSxmdW5jdGlvbihlLHQpe2xbIltvYmpl
Y3QgIit0KyJdIl09dC50b0xvd2VyQ2FzZSgpfSk7ZnVuY3Rpb24gaihlKXt2YXIgdD1lLmxlbmd0
aCxuPXgudHlwZShlKTtyZXR1cm4geC5pc1dpbmRvdyhlKT8hMToxPT09ZS5ub2RlVHlwZSYmdD8h
MDoiYXJyYXkiPT09bnx8ImZ1bmN0aW9uIiE9PW4mJigwPT09dHx8Im51bWJlciI9PXR5cGVvZiB0
JiZ0PjAmJnQtMSBpbiBlKX10PXgobyksZnVuY3Rpb24oZSx1bmRlZmluZWQpe3ZhciB0LG4scixp
LG8scyxhLHUsbCxjLGYscCxoLGQsZyxtLHksdj0ic2l6emxlIistbmV3IERhdGUsYj1lLmRvY3Vt
ZW50LHc9MCxUPTAsQz1hdCgpLGs9YXQoKSxOPWF0KCksRT0hMSxTPWZ1bmN0aW9uKCl7cmV0dXJu
IDB9LGo9dHlwZW9mIHVuZGVmaW5lZCxEPTE8PDMxLEE9e30uaGFzT3duUHJvcGVydHksTD1bXSxI
PUwucG9wLHE9TC5wdXNoLE89TC5wdXNoLEY9TC5zbGljZSxQPUwuaW5kZXhPZnx8ZnVuY3Rpb24o
ZSl7dmFyIHQ9MCxuPXRoaXMubGVuZ3RoO2Zvcig7bj50O3QrKylpZih0aGlzW3RdPT09ZSlyZXR1
cm4gdDtyZXR1cm4tMX0sUj0iY2hlY2tlZHxzZWxlY3RlZHxhc3luY3xhdXRvZm9jdXN8YXV0b3Bs
YXl8Y29udHJvbHN8ZGVmZXJ8ZGlzYWJsZWR8aGlkZGVufGlzbWFwfGxvb3B8bXVsdGlwbGV8b3Bl
bnxyZWFkb25seXxyZXF1aXJlZHxzY29wZWQiLE09IltcXHgyMFxcdFxcclxcblxcZl0iLFc9Iig/
OlxcXFwufFtcXHctXXxbXlxceDAwLVxceGEwXSkrIiwkPVcucmVwbGFjZSgidyIsIncjIiksQj0i
XFxbIitNKyIqKCIrVysiKSIrTSsiKig/OihbKl4kfCF+XT89KSIrTSsiKig/OihbJ1wiXSkoKD86
XFxcXC58W15cXFxcXSkqPylcXDN8KCIrJCsiKXwpfCkiK00rIipcXF0iLEk9IjooIitXKyIpKD86
XFwoKChbJ1wiXSkoKD86XFxcXC58W15cXFxcXSkqPylcXDN8KCg/OlxcXFwufFteXFxcXCgpW1xc
XV18IitCLnJlcGxhY2UoMyw4KSsiKSopfC4qKVxcKXwpIix6PVJlZ0V4cCgiXiIrTSsiK3woKD86
XnxbXlxcXFxdKSg/OlxcXFwuKSopIitNKyIrJCIsImciKSxfPVJlZ0V4cCgiXiIrTSsiKiwiK00r
IioiKSxYPVJlZ0V4cCgiXiIrTSsiKihbPit+XXwiK00rIikiK00rIioiKSxVPVJlZ0V4cChNKyIq
Wyt+XSIpLFk9UmVnRXhwKCI9IitNKyIqKFteXFxdJ1wiXSopIitNKyIqXFxdIiwiZyIpLFY9UmVn
RXhwKEkpLEc9UmVnRXhwKCJeIiskKyIkIiksSj17SUQ6UmVnRXhwKCJeIygiK1crIikiKSxDTEFT
UzpSZWdFeHAoIl5cXC4oIitXKyIpIiksVEFHOlJlZ0V4cCgiXigiK1cucmVwbGFjZSgidyIsIncq
IikrIikiKSxBVFRSOlJlZ0V4cCgiXiIrQiksUFNFVURPOlJlZ0V4cCgiXiIrSSksQ0hJTEQ6UmVn
RXhwKCJeOihvbmx5fGZpcnN0fGxhc3R8bnRofG50aC1sYXN0KS0oY2hpbGR8b2YtdHlwZSkoPzpc
XCgiK00rIiooZXZlbnxvZGR8KChbKy1dfCkoXFxkKilufCkiK00rIiooPzooWystXXwpIitNKyIq
KFxcZCspfCkpIitNKyIqXFwpfCkiLCJpIiksYm9vbDpSZWdFeHAoIl4oPzoiK1IrIikkIiwiaSIp
LG5lZWRzQ29udGV4dDpSZWdFeHAoIl4iK00rIipbPit+XXw6KGV2ZW58b2RkfGVxfGd0fGx0fG50
aHxmaXJzdHxsYXN0KSg/OlxcKCIrTSsiKigoPzotXFxkKT9cXGQqKSIrTSsiKlxcKXwpKD89W14t
XXwkKSIsImkiKX0sUT0vXltee10rXHtccypcW25hdGl2ZSBcdy8sSz0vXig/OiMoW1x3LV0rKXwo
XHcrKXxcLihbXHctXSspKSQvLFo9L14oPzppbnB1dHxzZWxlY3R8dGV4dGFyZWF8YnV0dG9uKSQv
aSxldD0vXmhcZCQvaSx0dD0vJ3xcXC9nLG50PVJlZ0V4cCgiXFxcXChbXFxkYS1mXXsxLDZ9IitN
KyI/fCgiK00rIil8LikiLCJpZyIpLHJ0PWZ1bmN0aW9uKGUsdCxuKXt2YXIgcj0iMHgiK3QtNjU1
MzY7cmV0dXJuIHIhPT1yfHxuP3Q6MD5yP1N0cmluZy5mcm9tQ2hhckNvZGUocis2NTUzNik6U3Ry
aW5nLmZyb21DaGFyQ29kZSg1NTI5NnxyPj4xMCw1NjMyMHwxMDIzJnIpfTt0cnl7Ty5hcHBseShM
PUYuY2FsbChiLmNoaWxkTm9kZXMpLGIuY2hpbGROb2RlcyksTFtiLmNoaWxkTm9kZXMubGVuZ3Ro
XS5ub2RlVHlwZX1jYXRjaChpdCl7Tz17YXBwbHk6TC5sZW5ndGg/ZnVuY3Rpb24oZSx0KXtxLmFw
cGx5KGUsRi5jYWxsKHQpKX06ZnVuY3Rpb24oZSx0KXt2YXIgbj1lLmxlbmd0aCxyPTA7d2hpbGUo
ZVtuKytdPXRbcisrXSk7ZS5sZW5ndGg9bi0xfX19ZnVuY3Rpb24gb3QoZSx0LHIsaSl7dmFyIG8s
cyxhLHUsbCxwLGcsbSx4LHc7aWYoKHQ/dC5vd25lckRvY3VtZW50fHx0OmIpIT09ZiYmYyh0KSx0
PXR8fGYscj1yfHxbXSwhZXx8InN0cmluZyIhPXR5cGVvZiBlKXJldHVybiByO2lmKDEhPT0odT10
Lm5vZGVUeXBlKSYmOSE9PXUpcmV0dXJuW107aWYoaCYmIWkpe2lmKG89Sy5leGVjKGUpKWlmKGE9
b1sxXSl7aWYoOT09PXUpe2lmKHM9dC5nZXRFbGVtZW50QnlJZChhKSwhc3x8IXMucGFyZW50Tm9k
ZSlyZXR1cm4gcjtpZihzLmlkPT09YSlyZXR1cm4gci5wdXNoKHMpLHJ9ZWxzZSBpZih0Lm93bmVy
RG9jdW1lbnQmJihzPXQub3duZXJEb2N1bWVudC5nZXRFbGVtZW50QnlJZChhKSkmJnkodCxzKSYm
cy5pZD09PWEpcmV0dXJuIHIucHVzaChzKSxyfWVsc2V7aWYob1syXSlyZXR1cm4gTy5hcHBseShy
LHQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoZSkpLHI7aWYoKGE9b1szXSkmJm4uZ2V0RWxlbWVudHNC
eUNsYXNzTmFtZSYmdC5nZXRFbGVtZW50c0J5Q2xhc3NOYW1lKXJldHVybiBPLmFwcGx5KHIsdC5n
ZXRFbGVtZW50c0J5Q2xhc3NOYW1lKGEpKSxyfWlmKG4ucXNhJiYoIWR8fCFkLnRlc3QoZSkpKXtp
ZihtPWc9dix4PXQsdz05PT09dSYmZSwxPT09dSYmIm9iamVjdCIhPT10Lm5vZGVOYW1lLnRvTG93
ZXJDYXNlKCkpe3A9dnQoZSksKGc9dC5nZXRBdHRyaWJ1dGUoImlkIikpP209Zy5yZXBsYWNlKHR0
LCJcXCQmIik6dC5zZXRBdHRyaWJ1dGUoImlkIixtKSxtPSJbaWQ9JyIrbSsiJ10gIixsPXAubGVu
Z3RoO3doaWxlKGwtLSlwW2xdPW0reHQocFtsXSk7eD1VLnRlc3QoZSkmJnQucGFyZW50Tm9kZXx8
dCx3PXAuam9pbigiLCIpfWlmKHcpdHJ5e3JldHVybiBPLmFwcGx5KHIseC5xdWVyeVNlbGVjdG9y
QWxsKHcpKSxyfWNhdGNoKFQpe31maW5hbGx5e2d8fHQucmVtb3ZlQXR0cmlidXRlKCJpZCIpfX19
cmV0dXJuIFN0KGUucmVwbGFjZSh6LCIkMSIpLHQscixpKX1mdW5jdGlvbiBzdChlKXtyZXR1cm4g
US50ZXN0KGUrIiIpfWZ1bmN0aW9uIGF0KCl7dmFyIGU9W107ZnVuY3Rpb24gdChuLHIpe3JldHVy
biBlLnB1c2gobis9IiAiKT5pLmNhY2hlTGVuZ3RoJiZkZWxldGUgdFtlLnNoaWZ0KCldLHRbbl09
cn1yZXR1cm4gdH1mdW5jdGlvbiB1dChlKXtyZXR1cm4gZVt2XT0hMCxlfWZ1bmN0aW9uIGx0KGUp
e3ZhciB0PWYuY3JlYXRlRWxlbWVudCgiZGl2Iik7dHJ5e3JldHVybiEhZSh0KX1jYXRjaChuKXty
ZXR1cm4hMX1maW5hbGx5e3QucGFyZW50Tm9kZSYmdC5wYXJlbnROb2RlLnJlbW92ZUNoaWxkKHQp
LHQ9bnVsbH19ZnVuY3Rpb24gY3QoZSx0LG4pe2U9ZS5zcGxpdCgifCIpO3ZhciByLG89ZS5sZW5n
dGgscz1uP251bGw6dDt3aGlsZShvLS0pKHI9aS5hdHRySGFuZGxlW2Vbb11dKSYmciE9PXR8fChp
LmF0dHJIYW5kbGVbZVtvXV09cyl9ZnVuY3Rpb24gZnQoZSx0KXt2YXIgbj1lLmdldEF0dHJpYnV0
ZU5vZGUodCk7cmV0dXJuIG4mJm4uc3BlY2lmaWVkP24udmFsdWU6ZVt0XT09PSEwP3QudG9Mb3dl
ckNhc2UoKTpudWxsfWZ1bmN0aW9uIHB0KGUsdCl7cmV0dXJuIGUuZ2V0QXR0cmlidXRlKHQsInR5
cGUiPT09dC50b0xvd2VyQ2FzZSgpPzE6Mil9ZnVuY3Rpb24gaHQoZSl7cmV0dXJuImlucHV0Ij09
PWUubm9kZU5hbWUudG9Mb3dlckNhc2UoKT9lLmRlZmF1bHRWYWx1ZTp1bmRlZmluZWR9ZnVuY3Rp
b24gZHQoZSx0KXt2YXIgbj10JiZlLHI9biYmMT09PWUubm9kZVR5cGUmJjE9PT10Lm5vZGVUeXBl
JiYofnQuc291cmNlSW5kZXh8fEQpLSh+ZS5zb3VyY2VJbmRleHx8RCk7aWYocilyZXR1cm4gcjtp
ZihuKXdoaWxlKG49bi5uZXh0U2libGluZylpZihuPT09dClyZXR1cm4tMTtyZXR1cm4gZT8xOi0x
fWZ1bmN0aW9uIGd0KGUpe3JldHVybiBmdW5jdGlvbih0KXt2YXIgbj10Lm5vZGVOYW1lLnRvTG93
ZXJDYXNlKCk7cmV0dXJuImlucHV0Ij09PW4mJnQudHlwZT09PWV9fWZ1bmN0aW9uIG10KGUpe3Jl
dHVybiBmdW5jdGlvbih0KXt2YXIgbj10Lm5vZGVOYW1lLnRvTG93ZXJDYXNlKCk7cmV0dXJuKCJp
bnB1dCI9PT1ufHwiYnV0dG9uIj09PW4pJiZ0LnR5cGU9PT1lfX1mdW5jdGlvbiB5dChlKXtyZXR1
cm4gdXQoZnVuY3Rpb24odCl7cmV0dXJuIHQ9K3QsdXQoZnVuY3Rpb24obixyKXt2YXIgaSxvPWUo
W10sbi5sZW5ndGgsdCkscz1vLmxlbmd0aDt3aGlsZShzLS0pbltpPW9bc11dJiYobltpXT0hKHJb
aV09bltpXSkpfSl9KX1zPW90LmlzWE1MPWZ1bmN0aW9uKGUpe3ZhciB0PWUmJihlLm93bmVyRG9j
dW1lbnR8fGUpLmRvY3VtZW50RWxlbWVudDtyZXR1cm4gdD8iSFRNTCIhPT10Lm5vZGVOYW1lOiEx
fSxuPW90LnN1cHBvcnQ9e30sYz1vdC5zZXREb2N1bWVudD1mdW5jdGlvbihlKXt2YXIgdD1lP2Uu
b3duZXJEb2N1bWVudHx8ZTpiO3JldHVybiB0IT09ZiYmOT09PXQubm9kZVR5cGUmJnQuZG9jdW1l
bnRFbGVtZW50PyhmPXQscD10LmRvY3VtZW50RWxlbWVudCxoPSFzKHQpLG4uYXR0cmlidXRlcz1s
dChmdW5jdGlvbihlKXtyZXR1cm4gZS5pbm5lckhUTUw9IjxhIGhyZWY9JyMnPjwvYT4iLGN0KCJ0
eXBlfGhyZWZ8aGVpZ2h0fHdpZHRoIixwdCwiIyI9PT1lLmZpcnN0Q2hpbGQuZ2V0QXR0cmlidXRl
KCJocmVmIikpLGN0KFIsZnQsbnVsbD09ZS5nZXRBdHRyaWJ1dGUoImRpc2FibGVkIikpLGUuY2xh
c3NOYW1lPSJpIiwhZS5nZXRBdHRyaWJ1dGUoImNsYXNzTmFtZSIpfSksbi5pbnB1dD1sdChmdW5j
dGlvbihlKXtyZXR1cm4gZS5pbm5lckhUTUw9IjxpbnB1dD4iLGUuZmlyc3RDaGlsZC5zZXRBdHRy
aWJ1dGUoInZhbHVlIiwiIiksIiI9PT1lLmZpcnN0Q2hpbGQuZ2V0QXR0cmlidXRlKCJ2YWx1ZSIp
fSksY3QoInZhbHVlIixodCxuLmF0dHJpYnV0ZXMmJm4uaW5wdXQpLG4uZ2V0RWxlbWVudHNCeVRh
Z05hbWU9bHQoZnVuY3Rpb24oZSl7cmV0dXJuIGUuYXBwZW5kQ2hpbGQodC5jcmVhdGVDb21tZW50
KCIiKSksIWUuZ2V0RWxlbWVudHNCeVRhZ05hbWUoIioiKS5sZW5ndGh9KSxuLmdldEVsZW1lbnRz
QnlDbGFzc05hbWU9bHQoZnVuY3Rpb24oZSl7cmV0dXJuIGUuaW5uZXJIVE1MPSI8ZGl2IGNsYXNz
PSdhJz48L2Rpdj48ZGl2IGNsYXNzPSdhIGknPjwvZGl2PiIsZS5maXJzdENoaWxkLmNsYXNzTmFt
ZT0iaSIsMj09PWUuZ2V0RWxlbWVudHNCeUNsYXNzTmFtZSgiaSIpLmxlbmd0aH0pLG4uZ2V0QnlJ
ZD1sdChmdW5jdGlvbihlKXtyZXR1cm4gcC5hcHBlbmRDaGlsZChlKS5pZD12LCF0LmdldEVsZW1l
bnRzQnlOYW1lfHwhdC5nZXRFbGVtZW50c0J5TmFtZSh2KS5sZW5ndGh9KSxuLmdldEJ5SWQ/KGku
ZmluZC5JRD1mdW5jdGlvbihlLHQpe2lmKHR5cGVvZiB0LmdldEVsZW1lbnRCeUlkIT09aiYmaCl7
dmFyIG49dC5nZXRFbGVtZW50QnlJZChlKTtyZXR1cm4gbiYmbi5wYXJlbnROb2RlP1tuXTpbXX19
LGkuZmlsdGVyLklEPWZ1bmN0aW9uKGUpe3ZhciB0PWUucmVwbGFjZShudCxydCk7cmV0dXJuIGZ1
bmN0aW9uKGUpe3JldHVybiBlLmdldEF0dHJpYnV0ZSgiaWQiKT09PXR9fSk6KGRlbGV0ZSBpLmZp
bmQuSUQsaS5maWx0ZXIuSUQ9ZnVuY3Rpb24oZSl7dmFyIHQ9ZS5yZXBsYWNlKG50LHJ0KTtyZXR1
cm4gZnVuY3Rpb24oZSl7dmFyIG49dHlwZW9mIGUuZ2V0QXR0cmlidXRlTm9kZSE9PWomJmUuZ2V0
QXR0cmlidXRlTm9kZSgiaWQiKTtyZXR1cm4gbiYmbi52YWx1ZT09PXR9fSksaS5maW5kLlRBRz1u
LmdldEVsZW1lbnRzQnlUYWdOYW1lP2Z1bmN0aW9uKGUsdCl7cmV0dXJuIHR5cGVvZiB0LmdldEVs
ZW1lbnRzQnlUYWdOYW1lIT09aj90LmdldEVsZW1lbnRzQnlUYWdOYW1lKGUpOnVuZGVmaW5lZH06
ZnVuY3Rpb24oZSx0KXt2YXIgbixyPVtdLGk9MCxvPXQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoZSk7
aWYoIioiPT09ZSl7d2hpbGUobj1vW2krK10pMT09PW4ubm9kZVR5cGUmJnIucHVzaChuKTtyZXR1
cm4gcn1yZXR1cm4gb30saS5maW5kLkNMQVNTPW4uZ2V0RWxlbWVudHNCeUNsYXNzTmFtZSYmZnVu
Y3Rpb24oZSx0KXtyZXR1cm4gdHlwZW9mIHQuZ2V0RWxlbWVudHNCeUNsYXNzTmFtZSE9PWomJmg/
dC5nZXRFbGVtZW50c0J5Q2xhc3NOYW1lKGUpOnVuZGVmaW5lZH0sZz1bXSxkPVtdLChuLnFzYT1z
dCh0LnF1ZXJ5U2VsZWN0b3JBbGwpKSYmKGx0KGZ1bmN0aW9uKGUpe2UuaW5uZXJIVE1MPSI8c2Vs
ZWN0PjxvcHRpb24gc2VsZWN0ZWQ9Jyc+PC9vcHRpb24+PC9zZWxlY3Q+IixlLnF1ZXJ5U2VsZWN0
b3JBbGwoIltzZWxlY3RlZF0iKS5sZW5ndGh8fGQucHVzaCgiXFxbIitNKyIqKD86dmFsdWV8IitS
KyIpIiksZS5xdWVyeVNlbGVjdG9yQWxsKCI6Y2hlY2tlZCIpLmxlbmd0aHx8ZC5wdXNoKCI6Y2hl
Y2tlZCIpfSksbHQoZnVuY3Rpb24oZSl7dmFyIG49dC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpO24u
c2V0QXR0cmlidXRlKCJ0eXBlIiwiaGlkZGVuIiksZS5hcHBlbmRDaGlsZChuKS5zZXRBdHRyaWJ1
dGUoInQiLCIiKSxlLnF1ZXJ5U2VsZWN0b3JBbGwoIlt0Xj0nJ10iKS5sZW5ndGgmJmQucHVzaCgi
WypeJF09IitNKyIqKD86Jyd8XCJcIikiKSxlLnF1ZXJ5U2VsZWN0b3JBbGwoIjplbmFibGVkIiku
bGVuZ3RofHxkLnB1c2goIjplbmFibGVkIiwiOmRpc2FibGVkIiksZS5xdWVyeVNlbGVjdG9yQWxs
KCIqLDp4IiksZC5wdXNoKCIsLio6Iil9KSksKG4ubWF0Y2hlc1NlbGVjdG9yPXN0KG09cC53ZWJr
aXRNYXRjaGVzU2VsZWN0b3J8fHAubW96TWF0Y2hlc1NlbGVjdG9yfHxwLm9NYXRjaGVzU2VsZWN0
b3J8fHAubXNNYXRjaGVzU2VsZWN0b3IpKSYmbHQoZnVuY3Rpb24oZSl7bi5kaXNjb25uZWN0ZWRN
YXRjaD1tLmNhbGwoZSwiZGl2IiksbS5jYWxsKGUsIltzIT0nJ106eCIpLGcucHVzaCgiIT0iLEkp
fSksZD1kLmxlbmd0aCYmUmVnRXhwKGQuam9pbigifCIpKSxnPWcubGVuZ3RoJiZSZWdFeHAoZy5q
b2luKCJ8IikpLHk9c3QocC5jb250YWlucyl8fHAuY29tcGFyZURvY3VtZW50UG9zaXRpb24/ZnVu
Y3Rpb24oZSx0KXt2YXIgbj05PT09ZS5ub2RlVHlwZT9lLmRvY3VtZW50RWxlbWVudDplLHI9dCYm
dC5wYXJlbnROb2RlO3JldHVybiBlPT09cnx8ISghcnx8MSE9PXIubm9kZVR5cGV8fCEobi5jb250
YWlucz9uLmNvbnRhaW5zKHIpOmUuY29tcGFyZURvY3VtZW50UG9zaXRpb24mJjE2JmUuY29tcGFy
ZURvY3VtZW50UG9zaXRpb24ocikpKX06ZnVuY3Rpb24oZSx0KXtpZih0KXdoaWxlKHQ9dC5wYXJl
bnROb2RlKWlmKHQ9PT1lKXJldHVybiEwO3JldHVybiExfSxuLnNvcnREZXRhY2hlZD1sdChmdW5j
dGlvbihlKXtyZXR1cm4gMSZlLmNvbXBhcmVEb2N1bWVudFBvc2l0aW9uKHQuY3JlYXRlRWxlbWVu
dCgiZGl2IikpfSksUz1wLmNvbXBhcmVEb2N1bWVudFBvc2l0aW9uP2Z1bmN0aW9uKGUscil7aWYo
ZT09PXIpcmV0dXJuIEU9ITAsMDt2YXIgaT1yLmNvbXBhcmVEb2N1bWVudFBvc2l0aW9uJiZlLmNv
bXBhcmVEb2N1bWVudFBvc2l0aW9uJiZlLmNvbXBhcmVEb2N1bWVudFBvc2l0aW9uKHIpO3JldHVy
biBpPzEmaXx8IW4uc29ydERldGFjaGVkJiZyLmNvbXBhcmVEb2N1bWVudFBvc2l0aW9uKGUpPT09
aT9lPT09dHx8eShiLGUpPy0xOnI9PT10fHx5KGIscik/MTpsP1AuY2FsbChsLGUpLVAuY2FsbChs
LHIpOjA6NCZpPy0xOjE6ZS5jb21wYXJlRG9jdW1lbnRQb3NpdGlvbj8tMToxfTpmdW5jdGlvbihl
LG4pe3ZhciByLGk9MCxvPWUucGFyZW50Tm9kZSxzPW4ucGFyZW50Tm9kZSxhPVtlXSx1PVtuXTtp
ZihlPT09bilyZXR1cm4gRT0hMCwwO2lmKCFvfHwhcylyZXR1cm4gZT09PXQ/LTE6bj09PXQ/MTpv
Py0xOnM/MTpsP1AuY2FsbChsLGUpLVAuY2FsbChsLG4pOjA7aWYobz09PXMpcmV0dXJuIGR0KGUs
bik7cj1lO3doaWxlKHI9ci5wYXJlbnROb2RlKWEudW5zaGlmdChyKTtyPW47d2hpbGUocj1yLnBh
cmVudE5vZGUpdS51bnNoaWZ0KHIpO3doaWxlKGFbaV09PT11W2ldKWkrKztyZXR1cm4gaT9kdChh
W2ldLHVbaV0pOmFbaV09PT1iPy0xOnVbaV09PT1iPzE6MH0sdCk6Zn0sb3QubWF0Y2hlcz1mdW5j
dGlvbihlLHQpe3JldHVybiBvdChlLG51bGwsbnVsbCx0KX0sb3QubWF0Y2hlc1NlbGVjdG9yPWZ1
bmN0aW9uKGUsdCl7aWYoKGUub3duZXJEb2N1bWVudHx8ZSkhPT1mJiZjKGUpLHQ9dC5yZXBsYWNl
KFksIj0nJDEnXSIpLCEoIW4ubWF0Y2hlc1NlbGVjdG9yfHwhaHx8ZyYmZy50ZXN0KHQpfHxkJiZk
LnRlc3QodCkpKXRyeXt2YXIgcj1tLmNhbGwoZSx0KTtpZihyfHxuLmRpc2Nvbm5lY3RlZE1hdGNo
fHxlLmRvY3VtZW50JiYxMSE9PWUuZG9jdW1lbnQubm9kZVR5cGUpcmV0dXJuIHJ9Y2F0Y2goaSl7
fXJldHVybiBvdCh0LGYsbnVsbCxbZV0pLmxlbmd0aD4wfSxvdC5jb250YWlucz1mdW5jdGlvbihl
LHQpe3JldHVybihlLm93bmVyRG9jdW1lbnR8fGUpIT09ZiYmYyhlKSx5KGUsdCl9LG90LmF0dHI9
ZnVuY3Rpb24oZSx0KXsoZS5vd25lckRvY3VtZW50fHxlKSE9PWYmJmMoZSk7dmFyIHI9aS5hdHRy
SGFuZGxlW3QudG9Mb3dlckNhc2UoKV0sbz1yJiZBLmNhbGwoaS5hdHRySGFuZGxlLHQudG9Mb3dl
ckNhc2UoKSk/cihlLHQsIWgpOnVuZGVmaW5lZDtyZXR1cm4gbz09PXVuZGVmaW5lZD9uLmF0dHJp
YnV0ZXN8fCFoP2UuZ2V0QXR0cmlidXRlKHQpOihvPWUuZ2V0QXR0cmlidXRlTm9kZSh0KSkmJm8u
c3BlY2lmaWVkP28udmFsdWU6bnVsbDpvfSxvdC5lcnJvcj1mdW5jdGlvbihlKXt0aHJvdyBFcnJv
cigiU3ludGF4IGVycm9yLCB1bnJlY29nbml6ZWQgZXhwcmVzc2lvbjogIitlKX0sb3QudW5pcXVl
U29ydD1mdW5jdGlvbihlKXt2YXIgdCxyPVtdLGk9MCxvPTA7aWYoRT0hbi5kZXRlY3REdXBsaWNh
dGVzLGw9IW4uc29ydFN0YWJsZSYmZS5zbGljZSgwKSxlLnNvcnQoUyksRSl7d2hpbGUodD1lW28r
K10pdD09PWVbb10mJihpPXIucHVzaChvKSk7d2hpbGUoaS0tKWUuc3BsaWNlKHJbaV0sMSl9cmV0
dXJuIGV9LG89b3QuZ2V0VGV4dD1mdW5jdGlvbihlKXt2YXIgdCxuPSIiLHI9MCxpPWUubm9kZVR5
cGU7aWYoaSl7aWYoMT09PWl8fDk9PT1pfHwxMT09PWkpe2lmKCJzdHJpbmciPT10eXBlb2YgZS50
ZXh0Q29udGVudClyZXR1cm4gZS50ZXh0Q29udGVudDtmb3IoZT1lLmZpcnN0Q2hpbGQ7ZTtlPWUu
bmV4dFNpYmxpbmcpbis9byhlKX1lbHNlIGlmKDM9PT1pfHw0PT09aSlyZXR1cm4gZS5ub2RlVmFs
dWV9ZWxzZSBmb3IoO3Q9ZVtyXTtyKyspbis9byh0KTtyZXR1cm4gbn0saT1vdC5zZWxlY3RvcnM9
e2NhY2hlTGVuZ3RoOjUwLGNyZWF0ZVBzZXVkbzp1dCxtYXRjaDpKLGF0dHJIYW5kbGU6e30sZmlu
ZDp7fSxyZWxhdGl2ZTp7Ij4iOntkaXI6InBhcmVudE5vZGUiLGZpcnN0OiEwfSwiICI6e2Rpcjoi
cGFyZW50Tm9kZSJ9LCIrIjp7ZGlyOiJwcmV2aW91c1NpYmxpbmciLGZpcnN0OiEwfSwifiI6e2Rp
cjoicHJldmlvdXNTaWJsaW5nIn19LHByZUZpbHRlcjp7QVRUUjpmdW5jdGlvbihlKXtyZXR1cm4g
ZVsxXT1lWzFdLnJlcGxhY2UobnQscnQpLGVbM109KGVbNF18fGVbNV18fCIiKS5yZXBsYWNlKG50
LHJ0KSwifj0iPT09ZVsyXSYmKGVbM109IiAiK2VbM10rIiAiKSxlLnNsaWNlKDAsNCl9LENISUxE
OmZ1bmN0aW9uKGUpe3JldHVybiBlWzFdPWVbMV0udG9Mb3dlckNhc2UoKSwibnRoIj09PWVbMV0u
c2xpY2UoMCwzKT8oZVszXXx8b3QuZXJyb3IoZVswXSksZVs0XT0rKGVbNF0/ZVs1XSsoZVs2XXx8
MSk6MiooImV2ZW4iPT09ZVszXXx8Im9kZCI9PT1lWzNdKSksZVs1XT0rKGVbN10rZVs4XXx8Im9k
ZCI9PT1lWzNdKSk6ZVszXSYmb3QuZXJyb3IoZVswXSksZX0sUFNFVURPOmZ1bmN0aW9uKGUpe3Zh
ciB0LG49IWVbNV0mJmVbMl07cmV0dXJuIEouQ0hJTEQudGVzdChlWzBdKT9udWxsOihlWzNdJiZl
WzRdIT09dW5kZWZpbmVkP2VbMl09ZVs0XTpuJiZWLnRlc3QobikmJih0PXZ0KG4sITApKSYmKHQ9
bi5pbmRleE9mKCIpIixuLmxlbmd0aC10KS1uLmxlbmd0aCkmJihlWzBdPWVbMF0uc2xpY2UoMCx0
KSxlWzJdPW4uc2xpY2UoMCx0KSksZS5zbGljZSgwLDMpKX19LGZpbHRlcjp7VEFHOmZ1bmN0aW9u
KGUpe3ZhciB0PWUucmVwbGFjZShudCxydCkudG9Mb3dlckNhc2UoKTtyZXR1cm4iKiI9PT1lP2Z1
bmN0aW9uKCl7cmV0dXJuITB9OmZ1bmN0aW9uKGUpe3JldHVybiBlLm5vZGVOYW1lJiZlLm5vZGVO
YW1lLnRvTG93ZXJDYXNlKCk9PT10fX0sQ0xBU1M6ZnVuY3Rpb24oZSl7dmFyIHQ9Q1tlKyIgIl07
cmV0dXJuIHR8fCh0PVJlZ0V4cCgiKF58IitNKyIpIitlKyIoIitNKyJ8JCkiKSkmJkMoZSxmdW5j
dGlvbihlKXtyZXR1cm4gdC50ZXN0KCJzdHJpbmciPT10eXBlb2YgZS5jbGFzc05hbWUmJmUuY2xh
c3NOYW1lfHx0eXBlb2YgZS5nZXRBdHRyaWJ1dGUhPT1qJiZlLmdldEF0dHJpYnV0ZSgiY2xhc3Mi
KXx8IiIpfSl9LEFUVFI6ZnVuY3Rpb24oZSx0LG4pe3JldHVybiBmdW5jdGlvbihyKXt2YXIgaT1v
dC5hdHRyKHIsZSk7cmV0dXJuIG51bGw9PWk/IiE9Ij09PXQ6dD8oaSs9IiIsIj0iPT09dD9pPT09
bjoiIT0iPT09dD9pIT09bjoiXj0iPT09dD9uJiYwPT09aS5pbmRleE9mKG4pOiIqPSI9PT10P24m
JmkuaW5kZXhPZihuKT4tMToiJD0iPT09dD9uJiZpLnNsaWNlKC1uLmxlbmd0aCk9PT1uOiJ+PSI9
PT10PygiICIraSsiICIpLmluZGV4T2Yobik+LTE6Inw9Ij09PXQ/aT09PW58fGkuc2xpY2UoMCxu
Lmxlbmd0aCsxKT09PW4rIi0iOiExKTohMH19LENISUxEOmZ1bmN0aW9uKGUsdCxuLHIsaSl7dmFy
IG89Im50aCIhPT1lLnNsaWNlKDAsMykscz0ibGFzdCIhPT1lLnNsaWNlKC00KSxhPSJvZi10eXBl
Ij09PXQ7cmV0dXJuIDE9PT1yJiYwPT09aT9mdW5jdGlvbihlKXtyZXR1cm4hIWUucGFyZW50Tm9k
ZX06ZnVuY3Rpb24odCxuLHUpe3ZhciBsLGMsZixwLGgsZCxnPW8hPT1zPyJuZXh0U2libGluZyI6
InByZXZpb3VzU2libGluZyIsbT10LnBhcmVudE5vZGUseT1hJiZ0Lm5vZGVOYW1lLnRvTG93ZXJD
YXNlKCkseD0hdSYmIWE7aWYobSl7aWYobyl7d2hpbGUoZyl7Zj10O3doaWxlKGY9ZltnXSlpZihh
P2Yubm9kZU5hbWUudG9Mb3dlckNhc2UoKT09PXk6MT09PWYubm9kZVR5cGUpcmV0dXJuITE7ZD1n
PSJvbmx5Ij09PWUmJiFkJiYibmV4dFNpYmxpbmcifXJldHVybiEwfWlmKGQ9W3M/bS5maXJzdENo
aWxkOm0ubGFzdENoaWxkXSxzJiZ4KXtjPW1bdl18fChtW3ZdPXt9KSxsPWNbZV18fFtdLGg9bFsw
XT09PXcmJmxbMV0scD1sWzBdPT09dyYmbFsyXSxmPWgmJm0uY2hpbGROb2Rlc1toXTt3aGlsZShm
PSsraCYmZiYmZltnXXx8KHA9aD0wKXx8ZC5wb3AoKSlpZigxPT09Zi5ub2RlVHlwZSYmKytwJiZm
PT09dCl7Y1tlXT1bdyxoLHBdO2JyZWFrfX1lbHNlIGlmKHgmJihsPSh0W3ZdfHwodFt2XT17fSkp
W2VdKSYmbFswXT09PXcpcD1sWzFdO2Vsc2Ugd2hpbGUoZj0rK2gmJmYmJmZbZ118fChwPWg9MCl8
fGQucG9wKCkpaWYoKGE/Zi5ub2RlTmFtZS50b0xvd2VyQ2FzZSgpPT09eToxPT09Zi5ub2RlVHlw
ZSkmJisrcCYmKHgmJigoZlt2XXx8KGZbdl09e30pKVtlXT1bdyxwXSksZj09PXQpKWJyZWFrO3Jl
dHVybiBwLT1pLHA9PT1yfHwwPT09cCVyJiZwL3I+PTB9fX0sUFNFVURPOmZ1bmN0aW9uKGUsdCl7
dmFyIG4scj1pLnBzZXVkb3NbZV18fGkuc2V0RmlsdGVyc1tlLnRvTG93ZXJDYXNlKCldfHxvdC5l
cnJvcigidW5zdXBwb3J0ZWQgcHNldWRvOiAiK2UpO3JldHVybiByW3ZdP3IodCk6ci5sZW5ndGg+
MT8obj1bZSxlLCIiLHRdLGkuc2V0RmlsdGVycy5oYXNPd25Qcm9wZXJ0eShlLnRvTG93ZXJDYXNl
KCkpP3V0KGZ1bmN0aW9uKGUsbil7dmFyIGksbz1yKGUsdCkscz1vLmxlbmd0aDt3aGlsZShzLS0p
aT1QLmNhbGwoZSxvW3NdKSxlW2ldPSEobltpXT1vW3NdKX0pOmZ1bmN0aW9uKGUpe3JldHVybiBy
KGUsMCxuKX0pOnJ9fSxwc2V1ZG9zOntub3Q6dXQoZnVuY3Rpb24oZSl7dmFyIHQ9W10sbj1bXSxy
PWEoZS5yZXBsYWNlKHosIiQxIikpO3JldHVybiByW3ZdP3V0KGZ1bmN0aW9uKGUsdCxuLGkpe3Zh
ciBvLHM9cihlLG51bGwsaSxbXSksYT1lLmxlbmd0aDt3aGlsZShhLS0pKG89c1thXSkmJihlW2Fd
PSEodFthXT1vKSl9KTpmdW5jdGlvbihlLGksbyl7cmV0dXJuIHRbMF09ZSxyKHQsbnVsbCxvLG4p
LCFuLnBvcCgpfX0pLGhhczp1dChmdW5jdGlvbihlKXtyZXR1cm4gZnVuY3Rpb24odCl7cmV0dXJu
IG90KGUsdCkubGVuZ3RoPjB9fSksY29udGFpbnM6dXQoZnVuY3Rpb24oZSl7cmV0dXJuIGZ1bmN0
aW9uKHQpe3JldHVybih0LnRleHRDb250ZW50fHx0LmlubmVyVGV4dHx8byh0KSkuaW5kZXhPZihl
KT4tMX19KSxsYW5nOnV0KGZ1bmN0aW9uKGUpe3JldHVybiBHLnRlc3QoZXx8IiIpfHxvdC5lcnJv
cigidW5zdXBwb3J0ZWQgbGFuZzogIitlKSxlPWUucmVwbGFjZShudCxydCkudG9Mb3dlckNhc2Uo
KSxmdW5jdGlvbih0KXt2YXIgbjtkbyBpZihuPWg/dC5sYW5nOnQuZ2V0QXR0cmlidXRlKCJ4bWw6
bGFuZyIpfHx0LmdldEF0dHJpYnV0ZSgibGFuZyIpKXJldHVybiBuPW4udG9Mb3dlckNhc2UoKSxu
PT09ZXx8MD09PW4uaW5kZXhPZihlKyItIik7d2hpbGUoKHQ9dC5wYXJlbnROb2RlKSYmMT09PXQu
bm9kZVR5cGUpO3JldHVybiExfX0pLHRhcmdldDpmdW5jdGlvbih0KXt2YXIgbj1lLmxvY2F0aW9u
JiZlLmxvY2F0aW9uLmhhc2g7cmV0dXJuIG4mJm4uc2xpY2UoMSk9PT10LmlkfSxyb290OmZ1bmN0
aW9uKGUpe3JldHVybiBlPT09cH0sZm9jdXM6ZnVuY3Rpb24oZSl7cmV0dXJuIGU9PT1mLmFjdGl2
ZUVsZW1lbnQmJighZi5oYXNGb2N1c3x8Zi5oYXNGb2N1cygpKSYmISEoZS50eXBlfHxlLmhyZWZ8
fH5lLnRhYkluZGV4KX0sZW5hYmxlZDpmdW5jdGlvbihlKXtyZXR1cm4gZS5kaXNhYmxlZD09PSEx
fSxkaXNhYmxlZDpmdW5jdGlvbihlKXtyZXR1cm4gZS5kaXNhYmxlZD09PSEwfSxjaGVja2VkOmZ1
bmN0aW9uKGUpe3ZhciB0PWUubm9kZU5hbWUudG9Mb3dlckNhc2UoKTtyZXR1cm4iaW5wdXQiPT09
dCYmISFlLmNoZWNrZWR8fCJvcHRpb24iPT09dCYmISFlLnNlbGVjdGVkfSxzZWxlY3RlZDpmdW5j
dGlvbihlKXtyZXR1cm4gZS5wYXJlbnROb2RlJiZlLnBhcmVudE5vZGUuc2VsZWN0ZWRJbmRleCxl
LnNlbGVjdGVkPT09ITB9LGVtcHR5OmZ1bmN0aW9uKGUpe2ZvcihlPWUuZmlyc3RDaGlsZDtlO2U9
ZS5uZXh0U2libGluZylpZihlLm5vZGVOYW1lPiJAInx8Mz09PWUubm9kZVR5cGV8fDQ9PT1lLm5v
ZGVUeXBlKXJldHVybiExO3JldHVybiEwfSxwYXJlbnQ6ZnVuY3Rpb24oZSl7cmV0dXJuIWkucHNl
dWRvcy5lbXB0eShlKX0saGVhZGVyOmZ1bmN0aW9uKGUpe3JldHVybiBldC50ZXN0KGUubm9kZU5h
bWUpfSxpbnB1dDpmdW5jdGlvbihlKXtyZXR1cm4gWi50ZXN0KGUubm9kZU5hbWUpfSxidXR0b246
ZnVuY3Rpb24oZSl7dmFyIHQ9ZS5ub2RlTmFtZS50b0xvd2VyQ2FzZSgpO3JldHVybiJpbnB1dCI9
PT10JiYiYnV0dG9uIj09PWUudHlwZXx8ImJ1dHRvbiI9PT10fSx0ZXh0OmZ1bmN0aW9uKGUpe3Zh
ciB0O3JldHVybiJpbnB1dCI9PT1lLm5vZGVOYW1lLnRvTG93ZXJDYXNlKCkmJiJ0ZXh0Ij09PWUu
dHlwZSYmKG51bGw9PSh0PWUuZ2V0QXR0cmlidXRlKCJ0eXBlIikpfHx0LnRvTG93ZXJDYXNlKCk9
PT1lLnR5cGUpfSxmaXJzdDp5dChmdW5jdGlvbigpe3JldHVyblswXX0pLGxhc3Q6eXQoZnVuY3Rp
b24oZSx0KXtyZXR1cm5bdC0xXX0pLGVxOnl0KGZ1bmN0aW9uKGUsdCxuKXtyZXR1cm5bMD5uP24r
dDpuXX0pLGV2ZW46eXQoZnVuY3Rpb24oZSx0KXt2YXIgbj0wO2Zvcig7dD5uO24rPTIpZS5wdXNo
KG4pO3JldHVybiBlfSksb2RkOnl0KGZ1bmN0aW9uKGUsdCl7dmFyIG49MTtmb3IoO3Q+bjtuKz0y
KWUucHVzaChuKTtyZXR1cm4gZX0pLGx0Onl0KGZ1bmN0aW9uKGUsdCxuKXt2YXIgcj0wPm4/bit0
Om47Zm9yKDstLXI+PTA7KWUucHVzaChyKTtyZXR1cm4gZX0pLGd0Onl0KGZ1bmN0aW9uKGUsdCxu
KXt2YXIgcj0wPm4/bit0Om47Zm9yKDt0PisrcjspZS5wdXNoKHIpO3JldHVybiBlfSl9fTtmb3Io
dCBpbntyYWRpbzohMCxjaGVja2JveDohMCxmaWxlOiEwLHBhc3N3b3JkOiEwLGltYWdlOiEwfSlp
LnBzZXVkb3NbdF09Z3QodCk7Zm9yKHQgaW57c3VibWl0OiEwLHJlc2V0OiEwfSlpLnBzZXVkb3Nb
dF09bXQodCk7ZnVuY3Rpb24gdnQoZSx0KXt2YXIgbixyLG8scyxhLHUsbCxjPWtbZSsiICJdO2lm
KGMpcmV0dXJuIHQ/MDpjLnNsaWNlKDApO2E9ZSx1PVtdLGw9aS5wcmVGaWx0ZXI7d2hpbGUoYSl7
KCFufHwocj1fLmV4ZWMoYSkpKSYmKHImJihhPWEuc2xpY2UoclswXS5sZW5ndGgpfHxhKSx1LnB1
c2gobz1bXSkpLG49ITEsKHI9WC5leGVjKGEpKSYmKG49ci5zaGlmdCgpLG8ucHVzaCh7dmFsdWU6
bix0eXBlOnJbMF0ucmVwbGFjZSh6LCIgIil9KSxhPWEuc2xpY2Uobi5sZW5ndGgpKTtmb3IocyBp
biBpLmZpbHRlcikhKHI9SltzXS5leGVjKGEpKXx8bFtzXSYmIShyPWxbc10ocikpfHwobj1yLnNo
aWZ0KCksby5wdXNoKHt2YWx1ZTpuLHR5cGU6cyxtYXRjaGVzOnJ9KSxhPWEuc2xpY2Uobi5sZW5n
dGgpKTtpZighbilicmVha31yZXR1cm4gdD9hLmxlbmd0aDphP290LmVycm9yKGUpOmsoZSx1KS5z
bGljZSgwKX1mdW5jdGlvbiB4dChlKXt2YXIgdD0wLG49ZS5sZW5ndGgscj0iIjtmb3IoO24+dDt0
Kyspcis9ZVt0XS52YWx1ZTtyZXR1cm4gcn1mdW5jdGlvbiBidChlLHQsbil7dmFyIGk9dC5kaXIs
bz1uJiYicGFyZW50Tm9kZSI9PT1pLHM9VCsrO3JldHVybiB0LmZpcnN0P2Z1bmN0aW9uKHQsbixy
KXt3aGlsZSh0PXRbaV0paWYoMT09PXQubm9kZVR5cGV8fG8pcmV0dXJuIGUodCxuLHIpfTpmdW5j
dGlvbih0LG4sYSl7dmFyIHUsbCxjLGY9dysiICIrcztpZihhKXt3aGlsZSh0PXRbaV0paWYoKDE9
PT10Lm5vZGVUeXBlfHxvKSYmZSh0LG4sYSkpcmV0dXJuITB9ZWxzZSB3aGlsZSh0PXRbaV0paWYo
MT09PXQubm9kZVR5cGV8fG8paWYoYz10W3ZdfHwodFt2XT17fSksKGw9Y1tpXSkmJmxbMF09PT1m
KXtpZigodT1sWzFdKT09PSEwfHx1PT09cilyZXR1cm4gdT09PSEwfWVsc2UgaWYobD1jW2ldPVtm
XSxsWzFdPWUodCxuLGEpfHxyLGxbMV09PT0hMClyZXR1cm4hMH19ZnVuY3Rpb24gd3QoZSl7cmV0
dXJuIGUubGVuZ3RoPjE/ZnVuY3Rpb24odCxuLHIpe3ZhciBpPWUubGVuZ3RoO3doaWxlKGktLSlp
ZighZVtpXSh0LG4scikpcmV0dXJuITE7cmV0dXJuITB9OmVbMF19ZnVuY3Rpb24gVHQoZSx0LG4s
cixpKXt2YXIgbyxzPVtdLGE9MCx1PWUubGVuZ3RoLGw9bnVsbCE9dDtmb3IoO3U+YTthKyspKG89
ZVthXSkmJighbnx8bihvLHIsaSkpJiYocy5wdXNoKG8pLGwmJnQucHVzaChhKSk7cmV0dXJuIHN9
ZnVuY3Rpb24gQ3QoZSx0LG4scixpLG8pe3JldHVybiByJiYhclt2XSYmKHI9Q3QocikpLGkmJiFp
W3ZdJiYoaT1DdChpLG8pKSx1dChmdW5jdGlvbihvLHMsYSx1KXt2YXIgbCxjLGYscD1bXSxoPVtd
LGQ9cy5sZW5ndGgsZz1vfHxFdCh0fHwiKiIsYS5ub2RlVHlwZT9bYV06YSxbXSksbT0hZXx8IW8m
JnQ/ZzpUdChnLHAsZSxhLHUpLHk9bj9pfHwobz9lOmR8fHIpP1tdOnM6bTtpZihuJiZuKG0seSxh
LHUpLHIpe2w9VHQoeSxoKSxyKGwsW10sYSx1KSxjPWwubGVuZ3RoO3doaWxlKGMtLSkoZj1sW2Nd
KSYmKHlbaFtjXV09IShtW2hbY11dPWYpKX1pZihvKXtpZihpfHxlKXtpZihpKXtsPVtdLGM9eS5s
ZW5ndGg7d2hpbGUoYy0tKShmPXlbY10pJiZsLnB1c2gobVtjXT1mKTtpKG51bGwseT1bXSxsLHUp
fWM9eS5sZW5ndGg7d2hpbGUoYy0tKShmPXlbY10pJiYobD1pP1AuY2FsbChvLGYpOnBbY10pPi0x
JiYob1tsXT0hKHNbbF09ZikpfX1lbHNlIHk9VHQoeT09PXM/eS5zcGxpY2UoZCx5Lmxlbmd0aCk6
eSksaT9pKG51bGwscyx5LHUpOk8uYXBwbHkocyx5KX0pfWZ1bmN0aW9uIGt0KGUpe3ZhciB0LG4s
cixvPWUubGVuZ3RoLHM9aS5yZWxhdGl2ZVtlWzBdLnR5cGVdLGE9c3x8aS5yZWxhdGl2ZVsiICJd
LGw9cz8xOjAsYz1idChmdW5jdGlvbihlKXtyZXR1cm4gZT09PXR9LGEsITApLGY9YnQoZnVuY3Rp
b24oZSl7cmV0dXJuIFAuY2FsbCh0LGUpPi0xfSxhLCEwKSxwPVtmdW5jdGlvbihlLG4scil7cmV0
dXJuIXMmJihyfHxuIT09dSl8fCgodD1uKS5ub2RlVHlwZT9jKGUsbixyKTpmKGUsbixyKSl9XTtm
b3IoO28+bDtsKyspaWYobj1pLnJlbGF0aXZlW2VbbF0udHlwZV0pcD1bYnQod3QocCksbildO2Vs
c2V7aWYobj1pLmZpbHRlcltlW2xdLnR5cGVdLmFwcGx5KG51bGwsZVtsXS5tYXRjaGVzKSxuW3Zd
KXtmb3Iocj0rK2w7bz5yO3IrKylpZihpLnJlbGF0aXZlW2Vbcl0udHlwZV0pYnJlYWs7cmV0dXJu
IEN0KGw+MSYmd3QocCksbD4xJiZ4dChlLnNsaWNlKDAsbC0xKS5jb25jYXQoe3ZhbHVlOiIgIj09
PWVbbC0yXS50eXBlPyIqIjoiIn0pKS5yZXBsYWNlKHosIiQxIiksbixyPmwmJmt0KGUuc2xpY2Uo
bCxyKSksbz5yJiZrdChlPWUuc2xpY2UocikpLG8+ciYmeHQoZSkpfXAucHVzaChuKX1yZXR1cm4g
d3QocCl9ZnVuY3Rpb24gTnQoZSx0KXt2YXIgbj0wLG89dC5sZW5ndGg+MCxzPWUubGVuZ3RoPjAs
YT1mdW5jdGlvbihhLGwsYyxwLGgpe3ZhciBkLGcsbSx5PVtdLHY9MCx4PSIwIixiPWEmJltdLFQ9
bnVsbCE9aCxDPXUsaz1hfHxzJiZpLmZpbmQuVEFHKCIqIixoJiZsLnBhcmVudE5vZGV8fGwpLE49
dys9bnVsbD09Qz8xOk1hdGgucmFuZG9tKCl8fC4xO2ZvcihUJiYodT1sIT09ZiYmbCxyPW4pO251
bGwhPShkPWtbeF0pO3grKyl7aWYocyYmZCl7Zz0wO3doaWxlKG09ZVtnKytdKWlmKG0oZCxsLGMp
KXtwLnB1c2goZCk7YnJlYWt9VCYmKHc9TixyPSsrbil9byYmKChkPSFtJiZkKSYmdi0tLGEmJmIu
cHVzaChkKSl9aWYodis9eCxvJiZ4IT09dil7Zz0wO3doaWxlKG09dFtnKytdKW0oYix5LGwsYyk7
aWYoYSl7aWYodj4wKXdoaWxlKHgtLSliW3hdfHx5W3hdfHwoeVt4XT1ILmNhbGwocCkpO3k9VHQo
eSl9Ty5hcHBseShwLHkpLFQmJiFhJiZ5Lmxlbmd0aD4wJiZ2K3QubGVuZ3RoPjEmJm90LnVuaXF1
ZVNvcnQocCl9cmV0dXJuIFQmJih3PU4sdT1DKSxifTtyZXR1cm4gbz91dChhKTphfWE9b3QuY29t
cGlsZT1mdW5jdGlvbihlLHQpe3ZhciBuLHI9W10saT1bXSxvPU5bZSsiICJdO2lmKCFvKXt0fHwo
dD12dChlKSksbj10Lmxlbmd0aDt3aGlsZShuLS0pbz1rdCh0W25dKSxvW3ZdP3IucHVzaChvKTpp
LnB1c2gobyk7bz1OKGUsTnQoaSxyKSl9cmV0dXJuIG99O2Z1bmN0aW9uIEV0KGUsdCxuKXt2YXIg
cj0wLGk9dC5sZW5ndGg7Zm9yKDtpPnI7cisrKW90KGUsdFtyXSxuKTtyZXR1cm4gbn1mdW5jdGlv
biBTdChlLHQscixvKXt2YXIgcyx1LGwsYyxmLHA9dnQoZSk7aWYoIW8mJjE9PT1wLmxlbmd0aCl7
aWYodT1wWzBdPXBbMF0uc2xpY2UoMCksdS5sZW5ndGg+MiYmIklEIj09PShsPXVbMF0pLnR5cGUm
Jm4uZ2V0QnlJZCYmOT09PXQubm9kZVR5cGUmJmgmJmkucmVsYXRpdmVbdVsxXS50eXBlXSl7aWYo
dD0oaS5maW5kLklEKGwubWF0Y2hlc1swXS5yZXBsYWNlKG50LHJ0KSx0KXx8W10pWzBdLCF0KXJl
dHVybiByO2U9ZS5zbGljZSh1LnNoaWZ0KCkudmFsdWUubGVuZ3RoKX1zPUoubmVlZHNDb250ZXh0
LnRlc3QoZSk/MDp1Lmxlbmd0aDt3aGlsZShzLS0pe2lmKGw9dVtzXSxpLnJlbGF0aXZlW2M9bC50
eXBlXSlicmVhaztpZigoZj1pLmZpbmRbY10pJiYobz1mKGwubWF0Y2hlc1swXS5yZXBsYWNlKG50
LHJ0KSxVLnRlc3QodVswXS50eXBlKSYmdC5wYXJlbnROb2RlfHx0KSkpe2lmKHUuc3BsaWNlKHMs
MSksZT1vLmxlbmd0aCYmeHQodSksIWUpcmV0dXJuIE8uYXBwbHkocixvKSxyO2JyZWFrfX19cmV0
dXJuIGEoZSxwKShvLHQsIWgscixVLnRlc3QoZSkpLHJ9aS5wc2V1ZG9zLm50aD1pLnBzZXVkb3Mu
ZXE7ZnVuY3Rpb24ganQoKXt9anQucHJvdG90eXBlPWkuZmlsdGVycz1pLnBzZXVkb3MsaS5zZXRG
aWx0ZXJzPW5ldyBqdCxuLnNvcnRTdGFibGU9di5zcGxpdCgiIikuc29ydChTKS5qb2luKCIiKT09
PXYsYygpLFswLDBdLnNvcnQoUyksbi5kZXRlY3REdXBsaWNhdGVzPUUseC5maW5kPW90LHguZXhw
cj1vdC5zZWxlY3RvcnMseC5leHByWyI6Il09eC5leHByLnBzZXVkb3MseC51bmlxdWU9b3QudW5p
cXVlU29ydCx4LnRleHQ9b3QuZ2V0VGV4dCx4LmlzWE1MRG9jPW90LmlzWE1MLHguY29udGFpbnM9
b3QuY29udGFpbnN9KGUpO3ZhciBEPXt9O2Z1bmN0aW9uIEEoZSl7dmFyIHQ9RFtlXT17fTtyZXR1
cm4geC5lYWNoKGUubWF0Y2godyl8fFtdLGZ1bmN0aW9uKGUsbil7dFtuXT0hMH0pLHR9eC5DYWxs
YmFja3M9ZnVuY3Rpb24oZSl7ZT0ic3RyaW5nIj09dHlwZW9mIGU/RFtlXXx8QShlKTp4LmV4dGVu
ZCh7fSxlKTt2YXIgdCxuLHIsaSxvLHMsYT1bXSx1PSFlLm9uY2UmJltdLGw9ZnVuY3Rpb24oZil7
Zm9yKHQ9ZS5tZW1vcnkmJmYsbj0hMCxzPWl8fDAsaT0wLG89YS5sZW5ndGgscj0hMDthJiZvPnM7
cysrKWlmKGFbc10uYXBwbHkoZlswXSxmWzFdKT09PSExJiZlLnN0b3BPbkZhbHNlKXt0PSExO2Jy
ZWFrfXI9ITEsYSYmKHU/dS5sZW5ndGgmJmwodS5zaGlmdCgpKTp0P2E9W106Yy5kaXNhYmxlKCkp
fSxjPXthZGQ6ZnVuY3Rpb24oKXtpZihhKXt2YXIgbj1hLmxlbmd0aDsoZnVuY3Rpb24gcyh0KXt4
LmVhY2godCxmdW5jdGlvbih0LG4pe3ZhciByPXgudHlwZShuKTsiZnVuY3Rpb24iPT09cj9lLnVu
aXF1ZSYmYy5oYXMobil8fGEucHVzaChuKTpuJiZuLmxlbmd0aCYmInN0cmluZyIhPT1yJiZzKG4p
fSl9KShhcmd1bWVudHMpLHI/bz1hLmxlbmd0aDp0JiYoaT1uLGwodCkpfXJldHVybiB0aGlzfSxy
ZW1vdmU6ZnVuY3Rpb24oKXtyZXR1cm4gYSYmeC5lYWNoKGFyZ3VtZW50cyxmdW5jdGlvbihlLHQp
e3ZhciBuO3doaWxlKChuPXguaW5BcnJheSh0LGEsbikpPi0xKWEuc3BsaWNlKG4sMSksciYmKG8+
PW4mJm8tLSxzPj1uJiZzLS0pfSksdGhpc30saGFzOmZ1bmN0aW9uKGUpe3JldHVybiBlP3guaW5B
cnJheShlLGEpPi0xOiEoIWF8fCFhLmxlbmd0aCl9LGVtcHR5OmZ1bmN0aW9uKCl7cmV0dXJuIGE9
W10sbz0wLHRoaXN9LGRpc2FibGU6ZnVuY3Rpb24oKXtyZXR1cm4gYT11PXQ9dW5kZWZpbmVkLHRo
aXN9LGRpc2FibGVkOmZ1bmN0aW9uKCl7cmV0dXJuIWF9LGxvY2s6ZnVuY3Rpb24oKXtyZXR1cm4g
dT11bmRlZmluZWQsdHx8Yy5kaXNhYmxlKCksdGhpc30sbG9ja2VkOmZ1bmN0aW9uKCl7cmV0dXJu
IXV9LGZpcmVXaXRoOmZ1bmN0aW9uKGUsdCl7cmV0dXJuIHQ9dHx8W10sdD1bZSx0LnNsaWNlP3Qu
c2xpY2UoKTp0XSwhYXx8biYmIXV8fChyP3UucHVzaCh0KTpsKHQpKSx0aGlzfSxmaXJlOmZ1bmN0
aW9uKCl7cmV0dXJuIGMuZmlyZVdpdGgodGhpcyxhcmd1bWVudHMpLHRoaXN9LGZpcmVkOmZ1bmN0
aW9uKCl7cmV0dXJuISFufX07cmV0dXJuIGN9LHguZXh0ZW5kKHtEZWZlcnJlZDpmdW5jdGlvbihl
KXt2YXIgdD1bWyJyZXNvbHZlIiwiZG9uZSIseC5DYWxsYmFja3MoIm9uY2UgbWVtb3J5IiksInJl
c29sdmVkIl0sWyJyZWplY3QiLCJmYWlsIix4LkNhbGxiYWNrcygib25jZSBtZW1vcnkiKSwicmVq
ZWN0ZWQiXSxbIm5vdGlmeSIsInByb2dyZXNzIix4LkNhbGxiYWNrcygibWVtb3J5IildXSxuPSJw
ZW5kaW5nIixyPXtzdGF0ZTpmdW5jdGlvbigpe3JldHVybiBufSxhbHdheXM6ZnVuY3Rpb24oKXty
ZXR1cm4gaS5kb25lKGFyZ3VtZW50cykuZmFpbChhcmd1bWVudHMpLHRoaXN9LHRoZW46ZnVuY3Rp
b24oKXt2YXIgZT1hcmd1bWVudHM7cmV0dXJuIHguRGVmZXJyZWQoZnVuY3Rpb24obil7eC5lYWNo
KHQsZnVuY3Rpb24odCxvKXt2YXIgcz1vWzBdLGE9eC5pc0Z1bmN0aW9uKGVbdF0pJiZlW3RdO2lb
b1sxXV0oZnVuY3Rpb24oKXt2YXIgZT1hJiZhLmFwcGx5KHRoaXMsYXJndW1lbnRzKTtlJiZ4Lmlz
RnVuY3Rpb24oZS5wcm9taXNlKT9lLnByb21pc2UoKS5kb25lKG4ucmVzb2x2ZSkuZmFpbChuLnJl
amVjdCkucHJvZ3Jlc3Mobi5ub3RpZnkpOm5bcysiV2l0aCJdKHRoaXM9PT1yP24ucHJvbWlzZSgp
OnRoaXMsYT9bZV06YXJndW1lbnRzKX0pfSksZT1udWxsfSkucHJvbWlzZSgpfSxwcm9taXNlOmZ1
bmN0aW9uKGUpe3JldHVybiBudWxsIT1lP3guZXh0ZW5kKGUscik6cn19LGk9e307cmV0dXJuIHIu
cGlwZT1yLnRoZW4seC5lYWNoKHQsZnVuY3Rpb24oZSxvKXt2YXIgcz1vWzJdLGE9b1szXTtyW29b
MV1dPXMuYWRkLGEmJnMuYWRkKGZ1bmN0aW9uKCl7bj1hfSx0WzFeZV1bMl0uZGlzYWJsZSx0WzJd
WzJdLmxvY2spLGlbb1swXV09ZnVuY3Rpb24oKXtyZXR1cm4gaVtvWzBdKyJXaXRoIl0odGhpcz09
PWk/cjp0aGlzLGFyZ3VtZW50cyksdGhpc30saVtvWzBdKyJXaXRoIl09cy5maXJlV2l0aH0pLHIu
cHJvbWlzZShpKSxlJiZlLmNhbGwoaSxpKSxpfSx3aGVuOmZ1bmN0aW9uKGUpe3ZhciB0PTAsbj1k
LmNhbGwoYXJndW1lbnRzKSxyPW4ubGVuZ3RoLGk9MSE9PXJ8fGUmJnguaXNGdW5jdGlvbihlLnBy
b21pc2UpP3I6MCxvPTE9PT1pP2U6eC5EZWZlcnJlZCgpLHM9ZnVuY3Rpb24oZSx0LG4pe3JldHVy
biBmdW5jdGlvbihyKXt0W2VdPXRoaXMsbltlXT1hcmd1bWVudHMubGVuZ3RoPjE/ZC5jYWxsKGFy
Z3VtZW50cyk6cixuPT09YT9vLm5vdGlmeVdpdGgodCxuKTotLWl8fG8ucmVzb2x2ZVdpdGgodCxu
KX19LGEsdSxsO2lmKHI+MSlmb3IoYT1BcnJheShyKSx1PUFycmF5KHIpLGw9QXJyYXkocik7cj50
O3QrKyluW3RdJiZ4LmlzRnVuY3Rpb24oblt0XS5wcm9taXNlKT9uW3RdLnByb21pc2UoKS5kb25l
KHModCxsLG4pKS5mYWlsKG8ucmVqZWN0KS5wcm9ncmVzcyhzKHQsdSxhKSk6LS1pO3JldHVybiBp
fHxvLnJlc29sdmVXaXRoKGwsbiksby5wcm9taXNlKCl9fSkseC5zdXBwb3J0PWZ1bmN0aW9uKHQp
e3ZhciBuPW8uY3JlYXRlRWxlbWVudCgiaW5wdXQiKSxyPW8uY3JlYXRlRG9jdW1lbnRGcmFnbWVu
dCgpLGk9by5jcmVhdGVFbGVtZW50KCJkaXYiKSxzPW8uY3JlYXRlRWxlbWVudCgic2VsZWN0Iiks
YT1zLmFwcGVuZENoaWxkKG8uY3JlYXRlRWxlbWVudCgib3B0aW9uIikpO3JldHVybiBuLnR5cGU/
KG4udHlwZT0iY2hlY2tib3giLHQuY2hlY2tPbj0iIiE9PW4udmFsdWUsdC5vcHRTZWxlY3RlZD1h
LnNlbGVjdGVkLHQucmVsaWFibGVNYXJnaW5SaWdodD0hMCx0LmJveFNpemluZ1JlbGlhYmxlPSEw
LHQucGl4ZWxQb3NpdGlvbj0hMSxuLmNoZWNrZWQ9ITAsdC5ub0Nsb25lQ2hlY2tlZD1uLmNsb25l
Tm9kZSghMCkuY2hlY2tlZCxzLmRpc2FibGVkPSEwLHQub3B0RGlzYWJsZWQ9IWEuZGlzYWJsZWQs
bj1vLmNyZWF0ZUVsZW1lbnQoImlucHV0Iiksbi52YWx1ZT0idCIsbi50eXBlPSJyYWRpbyIsdC5y
YWRpb1ZhbHVlPSJ0Ij09PW4udmFsdWUsbi5zZXRBdHRyaWJ1dGUoImNoZWNrZWQiLCJ0Iiksbi5z
ZXRBdHRyaWJ1dGUoIm5hbWUiLCJ0Iiksci5hcHBlbmRDaGlsZChuKSx0LmNoZWNrQ2xvbmU9ci5j
bG9uZU5vZGUoITApLmNsb25lTm9kZSghMCkubGFzdENoaWxkLmNoZWNrZWQsdC5mb2N1c2luQnVi
Ymxlcz0ib25mb2N1c2luImluIGUsaS5zdHlsZS5iYWNrZ3JvdW5kQ2xpcD0iY29udGVudC1ib3gi
LGkuY2xvbmVOb2RlKCEwKS5zdHlsZS5iYWNrZ3JvdW5kQ2xpcD0iIix0LmNsZWFyQ2xvbmVTdHls
ZT0iY29udGVudC1ib3giPT09aS5zdHlsZS5iYWNrZ3JvdW5kQ2xpcCx4KGZ1bmN0aW9uKCl7dmFy
IG4scixzPSJwYWRkaW5nOjA7bWFyZ2luOjA7Ym9yZGVyOjA7ZGlzcGxheTpibG9jazstd2Via2l0
LWJveC1zaXppbmc6Y29udGVudC1ib3g7LW1vei1ib3gtc2l6aW5nOmNvbnRlbnQtYm94O2JveC1z
aXppbmc6Y29udGVudC1ib3giLGE9by5nZXRFbGVtZW50c0J5VGFnTmFtZSgiYm9keSIpWzBdO2Em
JihuPW8uY3JlYXRlRWxlbWVudCgiZGl2Iiksbi5zdHlsZS5jc3NUZXh0PSJib3JkZXI6MDt3aWR0
aDowO2hlaWdodDowO3Bvc2l0aW9uOmFic29sdXRlO3RvcDowO2xlZnQ6LTk5OTlweDttYXJnaW4t
dG9wOjFweCIsYS5hcHBlbmRDaGlsZChuKS5hcHBlbmRDaGlsZChpKSxpLmlubmVySFRNTD0iIixp
LnN0eWxlLmNzc1RleHQ9Ii13ZWJraXQtYm94LXNpemluZzpib3JkZXItYm94Oy1tb3otYm94LXNp
emluZzpib3JkZXItYm94O2JveC1zaXppbmc6Ym9yZGVyLWJveDtwYWRkaW5nOjFweDtib3JkZXI6
MXB4O2Rpc3BsYXk6YmxvY2s7d2lkdGg6NHB4O21hcmdpbi10b3A6MSU7cG9zaXRpb246YWJzb2x1
dGU7dG9wOjElIix4LnN3YXAoYSxudWxsIT1hLnN0eWxlLnpvb20/e3pvb206MX06e30sZnVuY3Rp
b24oKXt0LmJveFNpemluZz00PT09aS5vZmZzZXRXaWR0aH0pLGUuZ2V0Q29tcHV0ZWRTdHlsZSYm
KHQucGl4ZWxQb3NpdGlvbj0iMSUiIT09KGUuZ2V0Q29tcHV0ZWRTdHlsZShpLG51bGwpfHx7fSku
dG9wLHQuYm94U2l6aW5nUmVsaWFibGU9IjRweCI9PT0oZS5nZXRDb21wdXRlZFN0eWxlKGksbnVs
bCl8fHt3aWR0aDoiNHB4In0pLndpZHRoLHI9aS5hcHBlbmRDaGlsZChvLmNyZWF0ZUVsZW1lbnQo
ImRpdiIpKSxyLnN0eWxlLmNzc1RleHQ9aS5zdHlsZS5jc3NUZXh0PXMsci5zdHlsZS5tYXJnaW5S
aWdodD1yLnN0eWxlLndpZHRoPSIwIixpLnN0eWxlLndpZHRoPSIxcHgiLHQucmVsaWFibGVNYXJn
aW5SaWdodD0hcGFyc2VGbG9hdCgoZS5nZXRDb21wdXRlZFN0eWxlKHIsbnVsbCl8fHt9KS5tYXJn
aW5SaWdodCkpLGEucmVtb3ZlQ2hpbGQobikpfSksdCk6dH0oe30pO3ZhciBMLEgscT0vKD86XHtb
XHNcU10qXH18XFtbXHNcU10qXF0pJC8sTz0vKFtBLVpdKS9nO2Z1bmN0aW9uIEYoKXtPYmplY3Qu
ZGVmaW5lUHJvcGVydHkodGhpcy5jYWNoZT17fSwwLHtnZXQ6ZnVuY3Rpb24oKXtyZXR1cm57fX19
KSx0aGlzLmV4cGFuZG89eC5leHBhbmRvK01hdGgucmFuZG9tKCl9Ri51aWQ9MSxGLmFjY2VwdHM9
ZnVuY3Rpb24oZSl7cmV0dXJuIGUubm9kZVR5cGU/MT09PWUubm9kZVR5cGV8fDk9PT1lLm5vZGVU
eXBlOiEwfSxGLnByb3RvdHlwZT17a2V5OmZ1bmN0aW9uKGUpe2lmKCFGLmFjY2VwdHMoZSkpcmV0
dXJuIDA7dmFyIHQ9e30sbj1lW3RoaXMuZXhwYW5kb107aWYoIW4pe249Ri51aWQrKzt0cnl7dFt0
aGlzLmV4cGFuZG9dPXt2YWx1ZTpufSxPYmplY3QuZGVmaW5lUHJvcGVydGllcyhlLHQpfWNhdGNo
KHIpe3RbdGhpcy5leHBhbmRvXT1uLHguZXh0ZW5kKGUsdCl9fXJldHVybiB0aGlzLmNhY2hlW25d
fHwodGhpcy5jYWNoZVtuXT17fSksbn0sc2V0OmZ1bmN0aW9uKGUsdCxuKXt2YXIgcixpPXRoaXMu
a2V5KGUpLG89dGhpcy5jYWNoZVtpXTtpZigic3RyaW5nIj09dHlwZW9mIHQpb1t0XT1uO2Vsc2Ug
aWYoeC5pc0VtcHR5T2JqZWN0KG8pKXguZXh0ZW5kKHRoaXMuY2FjaGVbaV0sdCk7ZWxzZSBmb3Io
ciBpbiB0KW9bcl09dFtyXTtyZXR1cm4gb30sZ2V0OmZ1bmN0aW9uKGUsdCl7dmFyIG49dGhpcy5j
YWNoZVt0aGlzLmtleShlKV07cmV0dXJuIHQ9PT11bmRlZmluZWQ/bjpuW3RdfSxhY2Nlc3M6ZnVu
Y3Rpb24oZSx0LG4pe3JldHVybiB0PT09dW5kZWZpbmVkfHx0JiYic3RyaW5nIj09dHlwZW9mIHQm
Jm49PT11bmRlZmluZWQ/dGhpcy5nZXQoZSx0KToodGhpcy5zZXQoZSx0LG4pLG4hPT11bmRlZmlu
ZWQ/bjp0KX0scmVtb3ZlOmZ1bmN0aW9uKGUsdCl7dmFyIG4scixpLG89dGhpcy5rZXkoZSkscz10
aGlzLmNhY2hlW29dO2lmKHQ9PT11bmRlZmluZWQpdGhpcy5jYWNoZVtvXT17fTtlbHNle3guaXNB
cnJheSh0KT9yPXQuY29uY2F0KHQubWFwKHguY2FtZWxDYXNlKSk6KGk9eC5jYW1lbENhc2UodCks
dCBpbiBzP3I9W3QsaV06KHI9aSxyPXIgaW4gcz9bcl06ci5tYXRjaCh3KXx8W10pKSxuPXIubGVu
Z3RoO3doaWxlKG4tLSlkZWxldGUgc1tyW25dXX19LGhhc0RhdGE6ZnVuY3Rpb24oZSl7cmV0dXJu
IXguaXNFbXB0eU9iamVjdCh0aGlzLmNhY2hlW2VbdGhpcy5leHBhbmRvXV18fHt9KX0sZGlzY2Fy
ZDpmdW5jdGlvbihlKXtlW3RoaXMuZXhwYW5kb10mJmRlbGV0ZSB0aGlzLmNhY2hlW2VbdGhpcy5l
eHBhbmRvXV19fSxMPW5ldyBGLEg9bmV3IEYseC5leHRlbmQoe2FjY2VwdERhdGE6Ri5hY2NlcHRz
LGhhc0RhdGE6ZnVuY3Rpb24oZSl7cmV0dXJuIEwuaGFzRGF0YShlKXx8SC5oYXNEYXRhKGUpfSxk
YXRhOmZ1bmN0aW9uKGUsdCxuKXtyZXR1cm4gTC5hY2Nlc3MoZSx0LG4pfSxyZW1vdmVEYXRhOmZ1
bmN0aW9uKGUsdCl7TC5yZW1vdmUoZSx0KX0sX2RhdGE6ZnVuY3Rpb24oZSx0LG4pe3JldHVybiBI
LmFjY2VzcyhlLHQsbil9LF9yZW1vdmVEYXRhOmZ1bmN0aW9uKGUsdCl7SC5yZW1vdmUoZSx0KX19
KSx4LmZuLmV4dGVuZCh7ZGF0YTpmdW5jdGlvbihlLHQpe3ZhciBuLHIsaT10aGlzWzBdLG89MCxz
PW51bGw7aWYoZT09PXVuZGVmaW5lZCl7aWYodGhpcy5sZW5ndGgmJihzPUwuZ2V0KGkpLDE9PT1p
Lm5vZGVUeXBlJiYhSC5nZXQoaSwiaGFzRGF0YUF0dHJzIikpKXtmb3Iobj1pLmF0dHJpYnV0ZXM7
bi5sZW5ndGg+bztvKyspcj1uW29dLm5hbWUsMD09PXIuaW5kZXhPZigiZGF0YS0iKSYmKHI9eC5j
YW1lbENhc2Uoci5zbGljZSg1KSksUChpLHIsc1tyXSkpO0guc2V0KGksImhhc0RhdGFBdHRycyIs
ITApfXJldHVybiBzfXJldHVybiJvYmplY3QiPT10eXBlb2YgZT90aGlzLmVhY2goZnVuY3Rpb24o
KXtMLnNldCh0aGlzLGUpfSk6eC5hY2Nlc3ModGhpcyxmdW5jdGlvbih0KXt2YXIgbixyPXguY2Ft
ZWxDYXNlKGUpO2lmKGkmJnQ9PT11bmRlZmluZWQpe2lmKG49TC5nZXQoaSxlKSxuIT09dW5kZWZp
bmVkKXJldHVybiBuO2lmKG49TC5nZXQoaSxyKSxuIT09dW5kZWZpbmVkKXJldHVybiBuO2lmKG49
UChpLHIsdW5kZWZpbmVkKSxuIT09dW5kZWZpbmVkKXJldHVybiBufWVsc2UgdGhpcy5lYWNoKGZ1
bmN0aW9uKCl7dmFyIG49TC5nZXQodGhpcyxyKTtMLnNldCh0aGlzLHIsdCksLTEhPT1lLmluZGV4
T2YoIi0iKSYmbiE9PXVuZGVmaW5lZCYmTC5zZXQodGhpcyxlLHQpfSl9LG51bGwsdCxhcmd1bWVu
dHMubGVuZ3RoPjEsbnVsbCwhMCl9LHJlbW92ZURhdGE6ZnVuY3Rpb24oZSl7cmV0dXJuIHRoaXMu
ZWFjaChmdW5jdGlvbigpe0wucmVtb3ZlKHRoaXMsZSl9KX19KTtmdW5jdGlvbiBQKGUsdCxuKXt2
YXIgcjtpZihuPT09dW5kZWZpbmVkJiYxPT09ZS5ub2RlVHlwZSlpZihyPSJkYXRhLSIrdC5yZXBs
YWNlKE8sIi0kMSIpLnRvTG93ZXJDYXNlKCksbj1lLmdldEF0dHJpYnV0ZShyKSwic3RyaW5nIj09
dHlwZW9mIG4pe3RyeXtuPSJ0cnVlIj09PW4/ITA6ImZhbHNlIj09PW4/ITE6Im51bGwiPT09bj9u
dWxsOituKyIiPT09bj8rbjpxLnRlc3Qobik/SlNPTi5wYXJzZShuKTpufWNhdGNoKGkpe31MLnNl
dChlLHQsbil9ZWxzZSBuPXVuZGVmaW5lZDtyZXR1cm4gbn14LmV4dGVuZCh7cXVldWU6ZnVuY3Rp
b24oZSx0LG4pe3ZhciByO3JldHVybiBlPyh0PSh0fHwiZngiKSsicXVldWUiLHI9SC5nZXQoZSx0
KSxuJiYoIXJ8fHguaXNBcnJheShuKT9yPUguYWNjZXNzKGUsdCx4Lm1ha2VBcnJheShuKSk6ci5w
dXNoKG4pKSxyfHxbXSk6dW5kZWZpbmVkfSxkZXF1ZXVlOmZ1bmN0aW9uKGUsdCl7dD10fHwiZngi
O3ZhciBuPXgucXVldWUoZSx0KSxyPW4ubGVuZ3RoLGk9bi5zaGlmdCgpLG89eC5fcXVldWVIb29r
cyhlLHQpLHM9ZnVuY3Rpb24oKXt4LmRlcXVldWUoZSx0KX07ImlucHJvZ3Jlc3MiPT09aSYmKGk9
bi5zaGlmdCgpLHItLSksby5jdXI9aSxpJiYoImZ4Ij09PXQmJm4udW5zaGlmdCgiaW5wcm9ncmVz
cyIpLGRlbGV0ZSBvLnN0b3AsaS5jYWxsKGUscyxvKSksIXImJm8mJm8uZW1wdHkuZmlyZSgpCn0s
X3F1ZXVlSG9va3M6ZnVuY3Rpb24oZSx0KXt2YXIgbj10KyJxdWV1ZUhvb2tzIjtyZXR1cm4gSC5n
ZXQoZSxuKXx8SC5hY2Nlc3MoZSxuLHtlbXB0eTp4LkNhbGxiYWNrcygib25jZSBtZW1vcnkiKS5h
ZGQoZnVuY3Rpb24oKXtILnJlbW92ZShlLFt0KyJxdWV1ZSIsbl0pfSl9KX19KSx4LmZuLmV4dGVu
ZCh7cXVldWU6ZnVuY3Rpb24oZSx0KXt2YXIgbj0yO3JldHVybiJzdHJpbmciIT10eXBlb2YgZSYm
KHQ9ZSxlPSJmeCIsbi0tKSxuPmFyZ3VtZW50cy5sZW5ndGg/eC5xdWV1ZSh0aGlzWzBdLGUpOnQ9
PT11bmRlZmluZWQ/dGhpczp0aGlzLmVhY2goZnVuY3Rpb24oKXt2YXIgbj14LnF1ZXVlKHRoaXMs
ZSx0KTt4Ll9xdWV1ZUhvb2tzKHRoaXMsZSksImZ4Ij09PWUmJiJpbnByb2dyZXNzIiE9PW5bMF0m
JnguZGVxdWV1ZSh0aGlzLGUpfSl9LGRlcXVldWU6ZnVuY3Rpb24oZSl7cmV0dXJuIHRoaXMuZWFj
aChmdW5jdGlvbigpe3guZGVxdWV1ZSh0aGlzLGUpfSl9LGRlbGF5OmZ1bmN0aW9uKGUsdCl7cmV0
dXJuIGU9eC5meD94LmZ4LnNwZWVkc1tlXXx8ZTplLHQ9dHx8ImZ4Iix0aGlzLnF1ZXVlKHQsZnVu
Y3Rpb24odCxuKXt2YXIgcj1zZXRUaW1lb3V0KHQsZSk7bi5zdG9wPWZ1bmN0aW9uKCl7Y2xlYXJU
aW1lb3V0KHIpfX0pfSxjbGVhclF1ZXVlOmZ1bmN0aW9uKGUpe3JldHVybiB0aGlzLnF1ZXVlKGV8
fCJmeCIsW10pfSxwcm9taXNlOmZ1bmN0aW9uKGUsdCl7dmFyIG4scj0xLGk9eC5EZWZlcnJlZCgp
LG89dGhpcyxzPXRoaXMubGVuZ3RoLGE9ZnVuY3Rpb24oKXstLXJ8fGkucmVzb2x2ZVdpdGgobyxb
b10pfTsic3RyaW5nIiE9dHlwZW9mIGUmJih0PWUsZT11bmRlZmluZWQpLGU9ZXx8ImZ4Ijt3aGls
ZShzLS0pbj1ILmdldChvW3NdLGUrInF1ZXVlSG9va3MiKSxuJiZuLmVtcHR5JiYocisrLG4uZW1w
dHkuYWRkKGEpKTtyZXR1cm4gYSgpLGkucHJvbWlzZSh0KX19KTt2YXIgUixNLFc9L1tcdFxyXG5c
Zl0vZywkPS9cci9nLEI9L14oPzppbnB1dHxzZWxlY3R8dGV4dGFyZWF8YnV0dG9uKSQvaTt4LmZu
LmV4dGVuZCh7YXR0cjpmdW5jdGlvbihlLHQpe3JldHVybiB4LmFjY2Vzcyh0aGlzLHguYXR0cixl
LHQsYXJndW1lbnRzLmxlbmd0aD4xKX0scmVtb3ZlQXR0cjpmdW5jdGlvbihlKXtyZXR1cm4gdGhp
cy5lYWNoKGZ1bmN0aW9uKCl7eC5yZW1vdmVBdHRyKHRoaXMsZSl9KX0scHJvcDpmdW5jdGlvbihl
LHQpe3JldHVybiB4LmFjY2Vzcyh0aGlzLHgucHJvcCxlLHQsYXJndW1lbnRzLmxlbmd0aD4xKX0s
cmVtb3ZlUHJvcDpmdW5jdGlvbihlKXtyZXR1cm4gdGhpcy5lYWNoKGZ1bmN0aW9uKCl7ZGVsZXRl
IHRoaXNbeC5wcm9wRml4W2VdfHxlXX0pfSxhZGRDbGFzczpmdW5jdGlvbihlKXt2YXIgdCxuLHIs
aSxvLHM9MCxhPXRoaXMubGVuZ3RoLHU9InN0cmluZyI9PXR5cGVvZiBlJiZlO2lmKHguaXNGdW5j
dGlvbihlKSlyZXR1cm4gdGhpcy5lYWNoKGZ1bmN0aW9uKHQpe3godGhpcykuYWRkQ2xhc3MoZS5j
YWxsKHRoaXMsdCx0aGlzLmNsYXNzTmFtZSkpfSk7aWYodSlmb3IodD0oZXx8IiIpLm1hdGNoKHcp
fHxbXTthPnM7cysrKWlmKG49dGhpc1tzXSxyPTE9PT1uLm5vZGVUeXBlJiYobi5jbGFzc05hbWU/
KCIgIituLmNsYXNzTmFtZSsiICIpLnJlcGxhY2UoVywiICIpOiIgIikpe289MDt3aGlsZShpPXRb
bysrXSkwPnIuaW5kZXhPZigiICIraSsiICIpJiYocis9aSsiICIpO24uY2xhc3NOYW1lPXgudHJp
bShyKX1yZXR1cm4gdGhpc30scmVtb3ZlQ2xhc3M6ZnVuY3Rpb24oZSl7dmFyIHQsbixyLGksbyxz
PTAsYT10aGlzLmxlbmd0aCx1PTA9PT1hcmd1bWVudHMubGVuZ3RofHwic3RyaW5nIj09dHlwZW9m
IGUmJmU7aWYoeC5pc0Z1bmN0aW9uKGUpKXJldHVybiB0aGlzLmVhY2goZnVuY3Rpb24odCl7eCh0
aGlzKS5yZW1vdmVDbGFzcyhlLmNhbGwodGhpcyx0LHRoaXMuY2xhc3NOYW1lKSl9KTtpZih1KWZv
cih0PShlfHwiIikubWF0Y2godyl8fFtdO2E+cztzKyspaWYobj10aGlzW3NdLHI9MT09PW4ubm9k
ZVR5cGUmJihuLmNsYXNzTmFtZT8oIiAiK24uY2xhc3NOYW1lKyIgIikucmVwbGFjZShXLCIgIik6
IiIpKXtvPTA7d2hpbGUoaT10W28rK10pd2hpbGUoci5pbmRleE9mKCIgIitpKyIgIik+PTApcj1y
LnJlcGxhY2UoIiAiK2krIiAiLCIgIik7bi5jbGFzc05hbWU9ZT94LnRyaW0ocik6IiJ9cmV0dXJu
IHRoaXN9LHRvZ2dsZUNsYXNzOmZ1bmN0aW9uKGUsdCl7dmFyIG49dHlwZW9mIGUsaT0iYm9vbGVh
biI9PXR5cGVvZiB0O3JldHVybiB4LmlzRnVuY3Rpb24oZSk/dGhpcy5lYWNoKGZ1bmN0aW9uKG4p
e3godGhpcykudG9nZ2xlQ2xhc3MoZS5jYWxsKHRoaXMsbix0aGlzLmNsYXNzTmFtZSx0KSx0KX0p
OnRoaXMuZWFjaChmdW5jdGlvbigpe2lmKCJzdHJpbmciPT09bil7dmFyIG8scz0wLGE9eCh0aGlz
KSx1PXQsbD1lLm1hdGNoKHcpfHxbXTt3aGlsZShvPWxbcysrXSl1PWk/dTohYS5oYXNDbGFzcyhv
KSxhW3U/ImFkZENsYXNzIjoicmVtb3ZlQ2xhc3MiXShvKX1lbHNlKG49PT1yfHwiYm9vbGVhbiI9
PT1uKSYmKHRoaXMuY2xhc3NOYW1lJiZILnNldCh0aGlzLCJfX2NsYXNzTmFtZV9fIix0aGlzLmNs
YXNzTmFtZSksdGhpcy5jbGFzc05hbWU9dGhpcy5jbGFzc05hbWV8fGU9PT0hMT8iIjpILmdldCh0
aGlzLCJfX2NsYXNzTmFtZV9fIil8fCIiKX0pfSxoYXNDbGFzczpmdW5jdGlvbihlKXt2YXIgdD0i
ICIrZSsiICIsbj0wLHI9dGhpcy5sZW5ndGg7Zm9yKDtyPm47bisrKWlmKDE9PT10aGlzW25dLm5v
ZGVUeXBlJiYoIiAiK3RoaXNbbl0uY2xhc3NOYW1lKyIgIikucmVwbGFjZShXLCIgIikuaW5kZXhP
Zih0KT49MClyZXR1cm4hMDtyZXR1cm4hMX0sdmFsOmZ1bmN0aW9uKGUpe3ZhciB0LG4scixpPXRo
aXNbMF07e2lmKGFyZ3VtZW50cy5sZW5ndGgpcmV0dXJuIHI9eC5pc0Z1bmN0aW9uKGUpLHRoaXMu
ZWFjaChmdW5jdGlvbihuKXt2YXIgaTsxPT09dGhpcy5ub2RlVHlwZSYmKGk9cj9lLmNhbGwodGhp
cyxuLHgodGhpcykudmFsKCkpOmUsbnVsbD09aT9pPSIiOiJudW1iZXIiPT10eXBlb2YgaT9pKz0i
Ijp4LmlzQXJyYXkoaSkmJihpPXgubWFwKGksZnVuY3Rpb24oZSl7cmV0dXJuIG51bGw9PWU/IiI6
ZSsiIn0pKSx0PXgudmFsSG9va3NbdGhpcy50eXBlXXx8eC52YWxIb29rc1t0aGlzLm5vZGVOYW1l
LnRvTG93ZXJDYXNlKCldLHQmJiJzZXQiaW4gdCYmdC5zZXQodGhpcyxpLCJ2YWx1ZSIpIT09dW5k
ZWZpbmVkfHwodGhpcy52YWx1ZT1pKSl9KTtpZihpKXJldHVybiB0PXgudmFsSG9va3NbaS50eXBl
XXx8eC52YWxIb29rc1tpLm5vZGVOYW1lLnRvTG93ZXJDYXNlKCldLHQmJiJnZXQiaW4gdCYmKG49
dC5nZXQoaSwidmFsdWUiKSkhPT11bmRlZmluZWQ/bjoobj1pLnZhbHVlLCJzdHJpbmciPT10eXBl
b2Ygbj9uLnJlcGxhY2UoJCwiIik6bnVsbD09bj8iIjpuKX19fSkseC5leHRlbmQoe3ZhbEhvb2tz
OntvcHRpb246e2dldDpmdW5jdGlvbihlKXt2YXIgdD1lLmF0dHJpYnV0ZXMudmFsdWU7cmV0dXJu
IXR8fHQuc3BlY2lmaWVkP2UudmFsdWU6ZS50ZXh0fX0sc2VsZWN0OntnZXQ6ZnVuY3Rpb24oZSl7
dmFyIHQsbixyPWUub3B0aW9ucyxpPWUuc2VsZWN0ZWRJbmRleCxvPSJzZWxlY3Qtb25lIj09PWUu
dHlwZXx8MD5pLHM9bz9udWxsOltdLGE9bz9pKzE6ci5sZW5ndGgsdT0wPmk/YTpvP2k6MDtmb3Io
O2E+dTt1KyspaWYobj1yW3VdLCEoIW4uc2VsZWN0ZWQmJnUhPT1pfHwoeC5zdXBwb3J0Lm9wdERp
c2FibGVkP24uZGlzYWJsZWQ6bnVsbCE9PW4uZ2V0QXR0cmlidXRlKCJkaXNhYmxlZCIpKXx8bi5w
YXJlbnROb2RlLmRpc2FibGVkJiZ4Lm5vZGVOYW1lKG4ucGFyZW50Tm9kZSwib3B0Z3JvdXAiKSkp
e2lmKHQ9eChuKS52YWwoKSxvKXJldHVybiB0O3MucHVzaCh0KX1yZXR1cm4gc30sc2V0OmZ1bmN0
aW9uKGUsdCl7dmFyIG4scixpPWUub3B0aW9ucyxvPXgubWFrZUFycmF5KHQpLHM9aS5sZW5ndGg7
d2hpbGUocy0tKXI9aVtzXSwoci5zZWxlY3RlZD14LmluQXJyYXkoeChyKS52YWwoKSxvKT49MCkm
JihuPSEwKTtyZXR1cm4gbnx8KGUuc2VsZWN0ZWRJbmRleD0tMSksb319fSxhdHRyOmZ1bmN0aW9u
KGUsdCxuKXt2YXIgaSxvLHM9ZS5ub2RlVHlwZTtpZihlJiYzIT09cyYmOCE9PXMmJjIhPT1zKXJl
dHVybiB0eXBlb2YgZS5nZXRBdHRyaWJ1dGU9PT1yP3gucHJvcChlLHQsbik6KDE9PT1zJiZ4Lmlz
WE1MRG9jKGUpfHwodD10LnRvTG93ZXJDYXNlKCksaT14LmF0dHJIb29rc1t0XXx8KHguZXhwci5t
YXRjaC5ib29sLnRlc3QodCk/TTpSKSksbj09PXVuZGVmaW5lZD9pJiYiZ2V0ImluIGkmJm51bGwh
PT0obz1pLmdldChlLHQpKT9vOihvPXguZmluZC5hdHRyKGUsdCksbnVsbD09bz91bmRlZmluZWQ6
byk6bnVsbCE9PW4/aSYmInNldCJpbiBpJiYobz1pLnNldChlLG4sdCkpIT09dW5kZWZpbmVkP286
KGUuc2V0QXR0cmlidXRlKHQsbisiIiksbik6KHgucmVtb3ZlQXR0cihlLHQpLHVuZGVmaW5lZCkp
fSxyZW1vdmVBdHRyOmZ1bmN0aW9uKGUsdCl7dmFyIG4scixpPTAsbz10JiZ0Lm1hdGNoKHcpO2lm
KG8mJjE9PT1lLm5vZGVUeXBlKXdoaWxlKG49b1tpKytdKXI9eC5wcm9wRml4W25dfHxuLHguZXhw
ci5tYXRjaC5ib29sLnRlc3QobikmJihlW3JdPSExKSxlLnJlbW92ZUF0dHJpYnV0ZShuKX0sYXR0
ckhvb2tzOnt0eXBlOntzZXQ6ZnVuY3Rpb24oZSx0KXtpZigheC5zdXBwb3J0LnJhZGlvVmFsdWUm
JiJyYWRpbyI9PT10JiZ4Lm5vZGVOYW1lKGUsImlucHV0Iikpe3ZhciBuPWUudmFsdWU7cmV0dXJu
IGUuc2V0QXR0cmlidXRlKCJ0eXBlIix0KSxuJiYoZS52YWx1ZT1uKSx0fX19fSxwcm9wRml4Onsi
Zm9yIjoiaHRtbEZvciIsImNsYXNzIjoiY2xhc3NOYW1lIn0scHJvcDpmdW5jdGlvbihlLHQsbil7
dmFyIHIsaSxvLHM9ZS5ub2RlVHlwZTtpZihlJiYzIT09cyYmOCE9PXMmJjIhPT1zKXJldHVybiBv
PTEhPT1zfHwheC5pc1hNTERvYyhlKSxvJiYodD14LnByb3BGaXhbdF18fHQsaT14LnByb3BIb29r
c1t0XSksbiE9PXVuZGVmaW5lZD9pJiYic2V0ImluIGkmJihyPWkuc2V0KGUsbix0KSkhPT11bmRl
ZmluZWQ/cjplW3RdPW46aSYmImdldCJpbiBpJiZudWxsIT09KHI9aS5nZXQoZSx0KSk/cjplW3Rd
fSxwcm9wSG9va3M6e3RhYkluZGV4OntnZXQ6ZnVuY3Rpb24oZSl7cmV0dXJuIGUuaGFzQXR0cmli
dXRlKCJ0YWJpbmRleCIpfHxCLnRlc3QoZS5ub2RlTmFtZSl8fGUuaHJlZj9lLnRhYkluZGV4Oi0x
fX19fSksTT17c2V0OmZ1bmN0aW9uKGUsdCxuKXtyZXR1cm4gdD09PSExP3gucmVtb3ZlQXR0cihl
LG4pOmUuc2V0QXR0cmlidXRlKG4sbiksbn19LHguZWFjaCh4LmV4cHIubWF0Y2guYm9vbC5zb3Vy
Y2UubWF0Y2goL1x3Ky9nKSxmdW5jdGlvbihlLHQpe3ZhciBuPXguZXhwci5hdHRySGFuZGxlW3Rd
fHx4LmZpbmQuYXR0cjt4LmV4cHIuYXR0ckhhbmRsZVt0XT1mdW5jdGlvbihlLHQscil7dmFyIGk9
eC5leHByLmF0dHJIYW5kbGVbdF0sbz1yP3VuZGVmaW5lZDooeC5leHByLmF0dHJIYW5kbGVbdF09
dW5kZWZpbmVkKSE9bihlLHQscik/dC50b0xvd2VyQ2FzZSgpOm51bGw7cmV0dXJuIHguZXhwci5h
dHRySGFuZGxlW3RdPWksb319KSx4LnN1cHBvcnQub3B0U2VsZWN0ZWR8fCh4LnByb3BIb29rcy5z
ZWxlY3RlZD17Z2V0OmZ1bmN0aW9uKGUpe3ZhciB0PWUucGFyZW50Tm9kZTtyZXR1cm4gdCYmdC5w
YXJlbnROb2RlJiZ0LnBhcmVudE5vZGUuc2VsZWN0ZWRJbmRleCxudWxsfX0pLHguZWFjaChbInRh
YkluZGV4IiwicmVhZE9ubHkiLCJtYXhMZW5ndGgiLCJjZWxsU3BhY2luZyIsImNlbGxQYWRkaW5n
Iiwicm93U3BhbiIsImNvbFNwYW4iLCJ1c2VNYXAiLCJmcmFtZUJvcmRlciIsImNvbnRlbnRFZGl0
YWJsZSJdLGZ1bmN0aW9uKCl7eC5wcm9wRml4W3RoaXMudG9Mb3dlckNhc2UoKV09dGhpc30pLHgu
ZWFjaChbInJhZGlvIiwiY2hlY2tib3giXSxmdW5jdGlvbigpe3gudmFsSG9va3NbdGhpc109e3Nl
dDpmdW5jdGlvbihlLHQpe3JldHVybiB4LmlzQXJyYXkodCk/ZS5jaGVja2VkPXguaW5BcnJheSh4
KGUpLnZhbCgpLHQpPj0wOnVuZGVmaW5lZH19LHguc3VwcG9ydC5jaGVja09ufHwoeC52YWxIb29r
c1t0aGlzXS5nZXQ9ZnVuY3Rpb24oZSl7cmV0dXJuIG51bGw9PT1lLmdldEF0dHJpYnV0ZSgidmFs
dWUiKT8ib24iOmUudmFsdWV9KX0pO3ZhciBJPS9ea2V5Lyx6PS9eKD86bW91c2V8Y29udGV4dG1l
bnUpfGNsaWNrLyxfPS9eKD86Zm9jdXNpbmZvY3VzfGZvY3Vzb3V0Ymx1cikkLyxYPS9eKFteLl0q
KSg/OlwuKC4rKXwpJC87ZnVuY3Rpb24gVSgpe3JldHVybiEwfWZ1bmN0aW9uIFkoKXtyZXR1cm4h
MX1mdW5jdGlvbiBWKCl7dHJ5e3JldHVybiBvLmFjdGl2ZUVsZW1lbnR9Y2F0Y2goZSl7fX14LmV2
ZW50PXtnbG9iYWw6e30sYWRkOmZ1bmN0aW9uKGUsdCxuLGksbyl7dmFyIHMsYSx1LGwsYyxmLHAs
aCxkLGcsbSx5PUguZ2V0KGUpO2lmKHkpe24uaGFuZGxlciYmKHM9bixuPXMuaGFuZGxlcixvPXMu
c2VsZWN0b3IpLG4uZ3VpZHx8KG4uZ3VpZD14Lmd1aWQrKyksKGw9eS5ldmVudHMpfHwobD15LmV2
ZW50cz17fSksKGE9eS5oYW5kbGUpfHwoYT15LmhhbmRsZT1mdW5jdGlvbihlKXtyZXR1cm4gdHlw
ZW9mIHg9PT1yfHxlJiZ4LmV2ZW50LnRyaWdnZXJlZD09PWUudHlwZT91bmRlZmluZWQ6eC5ldmVu
dC5kaXNwYXRjaC5hcHBseShhLmVsZW0sYXJndW1lbnRzKX0sYS5lbGVtPWUpLHQ9KHR8fCIiKS5t
YXRjaCh3KXx8WyIiXSxjPXQubGVuZ3RoO3doaWxlKGMtLSl1PVguZXhlYyh0W2NdKXx8W10sZD1t
PXVbMV0sZz0odVsyXXx8IiIpLnNwbGl0KCIuIikuc29ydCgpLGQmJihwPXguZXZlbnQuc3BlY2lh
bFtkXXx8e30sZD0obz9wLmRlbGVnYXRlVHlwZTpwLmJpbmRUeXBlKXx8ZCxwPXguZXZlbnQuc3Bl
Y2lhbFtkXXx8e30sZj14LmV4dGVuZCh7dHlwZTpkLG9yaWdUeXBlOm0sZGF0YTppLGhhbmRsZXI6
bixndWlkOm4uZ3VpZCxzZWxlY3RvcjpvLG5lZWRzQ29udGV4dDpvJiZ4LmV4cHIubWF0Y2gubmVl
ZHNDb250ZXh0LnRlc3QobyksbmFtZXNwYWNlOmcuam9pbigiLiIpfSxzKSwoaD1sW2RdKXx8KGg9
bFtkXT1bXSxoLmRlbGVnYXRlQ291bnQ9MCxwLnNldHVwJiZwLnNldHVwLmNhbGwoZSxpLGcsYSkh
PT0hMXx8ZS5hZGRFdmVudExpc3RlbmVyJiZlLmFkZEV2ZW50TGlzdGVuZXIoZCxhLCExKSkscC5h
ZGQmJihwLmFkZC5jYWxsKGUsZiksZi5oYW5kbGVyLmd1aWR8fChmLmhhbmRsZXIuZ3VpZD1uLmd1
aWQpKSxvP2guc3BsaWNlKGguZGVsZWdhdGVDb3VudCsrLDAsZik6aC5wdXNoKGYpLHguZXZlbnQu
Z2xvYmFsW2RdPSEwKTtlPW51bGx9fSxyZW1vdmU6ZnVuY3Rpb24oZSx0LG4scixpKXt2YXIgbyxz
LGEsdSxsLGMsZixwLGgsZCxnLG09SC5oYXNEYXRhKGUpJiZILmdldChlKTtpZihtJiYodT1tLmV2
ZW50cykpe3Q9KHR8fCIiKS5tYXRjaCh3KXx8WyIiXSxsPXQubGVuZ3RoO3doaWxlKGwtLSlpZihh
PVguZXhlYyh0W2xdKXx8W10saD1nPWFbMV0sZD0oYVsyXXx8IiIpLnNwbGl0KCIuIikuc29ydCgp
LGgpe2Y9eC5ldmVudC5zcGVjaWFsW2hdfHx7fSxoPShyP2YuZGVsZWdhdGVUeXBlOmYuYmluZFR5
cGUpfHxoLHA9dVtoXXx8W10sYT1hWzJdJiZSZWdFeHAoIihefFxcLikiK2Quam9pbigiXFwuKD86
LipcXC58KSIpKyIoXFwufCQpIikscz1vPXAubGVuZ3RoO3doaWxlKG8tLSljPXBbb10sIWkmJmch
PT1jLm9yaWdUeXBlfHxuJiZuLmd1aWQhPT1jLmd1aWR8fGEmJiFhLnRlc3QoYy5uYW1lc3BhY2Up
fHxyJiZyIT09Yy5zZWxlY3RvciYmKCIqKiIhPT1yfHwhYy5zZWxlY3Rvcil8fChwLnNwbGljZShv
LDEpLGMuc2VsZWN0b3ImJnAuZGVsZWdhdGVDb3VudC0tLGYucmVtb3ZlJiZmLnJlbW92ZS5jYWxs
KGUsYykpO3MmJiFwLmxlbmd0aCYmKGYudGVhcmRvd24mJmYudGVhcmRvd24uY2FsbChlLGQsbS5o
YW5kbGUpIT09ITF8fHgucmVtb3ZlRXZlbnQoZSxoLG0uaGFuZGxlKSxkZWxldGUgdVtoXSl9ZWxz
ZSBmb3IoaCBpbiB1KXguZXZlbnQucmVtb3ZlKGUsaCt0W2xdLG4sciwhMCk7eC5pc0VtcHR5T2Jq
ZWN0KHUpJiYoZGVsZXRlIG0uaGFuZGxlLEgucmVtb3ZlKGUsImV2ZW50cyIpKX19LHRyaWdnZXI6
ZnVuY3Rpb24odCxuLHIsaSl7dmFyIHMsYSx1LGwsYyxmLHAsaD1bcnx8b10sZD15LmNhbGwodCwi
dHlwZSIpP3QudHlwZTp0LGc9eS5jYWxsKHQsIm5hbWVzcGFjZSIpP3QubmFtZXNwYWNlLnNwbGl0
KCIuIik6W107aWYoYT11PXI9cnx8bywzIT09ci5ub2RlVHlwZSYmOCE9PXIubm9kZVR5cGUmJiFf
LnRlc3QoZCt4LmV2ZW50LnRyaWdnZXJlZCkmJihkLmluZGV4T2YoIi4iKT49MCYmKGc9ZC5zcGxp
dCgiLiIpLGQ9Zy5zaGlmdCgpLGcuc29ydCgpKSxjPTA+ZC5pbmRleE9mKCI6IikmJiJvbiIrZCx0
PXRbeC5leHBhbmRvXT90Om5ldyB4LkV2ZW50KGQsIm9iamVjdCI9PXR5cGVvZiB0JiZ0KSx0Lmlz
VHJpZ2dlcj1pPzI6Myx0Lm5hbWVzcGFjZT1nLmpvaW4oIi4iKSx0Lm5hbWVzcGFjZV9yZT10Lm5h
bWVzcGFjZT9SZWdFeHAoIihefFxcLikiK2cuam9pbigiXFwuKD86LipcXC58KSIpKyIoXFwufCQp
Iik6bnVsbCx0LnJlc3VsdD11bmRlZmluZWQsdC50YXJnZXR8fCh0LnRhcmdldD1yKSxuPW51bGw9
PW4/W3RdOngubWFrZUFycmF5KG4sW3RdKSxwPXguZXZlbnQuc3BlY2lhbFtkXXx8e30saXx8IXAu
dHJpZ2dlcnx8cC50cmlnZ2VyLmFwcGx5KHIsbikhPT0hMSkpe2lmKCFpJiYhcC5ub0J1YmJsZSYm
IXguaXNXaW5kb3cocikpe2ZvcihsPXAuZGVsZWdhdGVUeXBlfHxkLF8udGVzdChsK2QpfHwoYT1h
LnBhcmVudE5vZGUpO2E7YT1hLnBhcmVudE5vZGUpaC5wdXNoKGEpLHU9YTt1PT09KHIub3duZXJE
b2N1bWVudHx8bykmJmgucHVzaCh1LmRlZmF1bHRWaWV3fHx1LnBhcmVudFdpbmRvd3x8ZSl9cz0w
O3doaWxlKChhPWhbcysrXSkmJiF0LmlzUHJvcGFnYXRpb25TdG9wcGVkKCkpdC50eXBlPXM+MT9s
OnAuYmluZFR5cGV8fGQsZj0oSC5nZXQoYSwiZXZlbnRzIil8fHt9KVt0LnR5cGVdJiZILmdldChh
LCJoYW5kbGUiKSxmJiZmLmFwcGx5KGEsbiksZj1jJiZhW2NdLGYmJnguYWNjZXB0RGF0YShhKSYm
Zi5hcHBseSYmZi5hcHBseShhLG4pPT09ITEmJnQucHJldmVudERlZmF1bHQoKTtyZXR1cm4gdC50
eXBlPWQsaXx8dC5pc0RlZmF1bHRQcmV2ZW50ZWQoKXx8cC5fZGVmYXVsdCYmcC5fZGVmYXVsdC5h
cHBseShoLnBvcCgpLG4pIT09ITF8fCF4LmFjY2VwdERhdGEocil8fGMmJnguaXNGdW5jdGlvbihy
W2RdKSYmIXguaXNXaW5kb3cocikmJih1PXJbY10sdSYmKHJbY109bnVsbCkseC5ldmVudC50cmln
Z2VyZWQ9ZCxyW2RdKCkseC5ldmVudC50cmlnZ2VyZWQ9dW5kZWZpbmVkLHUmJihyW2NdPXUpKSx0
LnJlc3VsdH19LGRpc3BhdGNoOmZ1bmN0aW9uKGUpe2U9eC5ldmVudC5maXgoZSk7dmFyIHQsbixy
LGksbyxzPVtdLGE9ZC5jYWxsKGFyZ3VtZW50cyksdT0oSC5nZXQodGhpcywiZXZlbnRzIil8fHt9
KVtlLnR5cGVdfHxbXSxsPXguZXZlbnQuc3BlY2lhbFtlLnR5cGVdfHx7fTtpZihhWzBdPWUsZS5k
ZWxlZ2F0ZVRhcmdldD10aGlzLCFsLnByZURpc3BhdGNofHxsLnByZURpc3BhdGNoLmNhbGwodGhp
cyxlKSE9PSExKXtzPXguZXZlbnQuaGFuZGxlcnMuY2FsbCh0aGlzLGUsdSksdD0wO3doaWxlKChp
PXNbdCsrXSkmJiFlLmlzUHJvcGFnYXRpb25TdG9wcGVkKCkpe2UuY3VycmVudFRhcmdldD1pLmVs
ZW0sbj0wO3doaWxlKChvPWkuaGFuZGxlcnNbbisrXSkmJiFlLmlzSW1tZWRpYXRlUHJvcGFnYXRp
b25TdG9wcGVkKCkpKCFlLm5hbWVzcGFjZV9yZXx8ZS5uYW1lc3BhY2VfcmUudGVzdChvLm5hbWVz
cGFjZSkpJiYoZS5oYW5kbGVPYmo9byxlLmRhdGE9by5kYXRhLHI9KCh4LmV2ZW50LnNwZWNpYWxb
by5vcmlnVHlwZV18fHt9KS5oYW5kbGV8fG8uaGFuZGxlcikuYXBwbHkoaS5lbGVtLGEpLHIhPT11
bmRlZmluZWQmJihlLnJlc3VsdD1yKT09PSExJiYoZS5wcmV2ZW50RGVmYXVsdCgpLGUuc3RvcFBy
b3BhZ2F0aW9uKCkpKX1yZXR1cm4gbC5wb3N0RGlzcGF0Y2gmJmwucG9zdERpc3BhdGNoLmNhbGwo
dGhpcyxlKSxlLnJlc3VsdH19LGhhbmRsZXJzOmZ1bmN0aW9uKGUsdCl7dmFyIG4scixpLG8scz1b
XSxhPXQuZGVsZWdhdGVDb3VudCx1PWUudGFyZ2V0O2lmKGEmJnUubm9kZVR5cGUmJighZS5idXR0
b258fCJjbGljayIhPT1lLnR5cGUpKWZvcig7dSE9PXRoaXM7dT11LnBhcmVudE5vZGV8fHRoaXMp
aWYodS5kaXNhYmxlZCE9PSEwfHwiY2xpY2siIT09ZS50eXBlKXtmb3Iocj1bXSxuPTA7YT5uO24r
KylvPXRbbl0saT1vLnNlbGVjdG9yKyIgIixyW2ldPT09dW5kZWZpbmVkJiYocltpXT1vLm5lZWRz
Q29udGV4dD94KGksdGhpcykuaW5kZXgodSk+PTA6eC5maW5kKGksdGhpcyxudWxsLFt1XSkubGVu
Z3RoKSxyW2ldJiZyLnB1c2gobyk7ci5sZW5ndGgmJnMucHVzaCh7ZWxlbTp1LGhhbmRsZXJzOnJ9
KX1yZXR1cm4gdC5sZW5ndGg+YSYmcy5wdXNoKHtlbGVtOnRoaXMsaGFuZGxlcnM6dC5zbGljZShh
KX0pLHN9LHByb3BzOiJhbHRLZXkgYnViYmxlcyBjYW5jZWxhYmxlIGN0cmxLZXkgY3VycmVudFRh
cmdldCBldmVudFBoYXNlIG1ldGFLZXkgcmVsYXRlZFRhcmdldCBzaGlmdEtleSB0YXJnZXQgdGlt
ZVN0YW1wIHZpZXcgd2hpY2giLnNwbGl0KCIgIiksZml4SG9va3M6e30sa2V5SG9va3M6e3Byb3Bz
OiJjaGFyIGNoYXJDb2RlIGtleSBrZXlDb2RlIi5zcGxpdCgiICIpLGZpbHRlcjpmdW5jdGlvbihl
LHQpe3JldHVybiBudWxsPT1lLndoaWNoJiYoZS53aGljaD1udWxsIT10LmNoYXJDb2RlP3QuY2hh
ckNvZGU6dC5rZXlDb2RlKSxlfX0sbW91c2VIb29rczp7cHJvcHM6ImJ1dHRvbiBidXR0b25zIGNs
aWVudFggY2xpZW50WSBvZmZzZXRYIG9mZnNldFkgcGFnZVggcGFnZVkgc2NyZWVuWCBzY3JlZW5Z
IHRvRWxlbWVudCIuc3BsaXQoIiAiKSxmaWx0ZXI6ZnVuY3Rpb24oZSx0KXt2YXIgbixyLGkscz10
LmJ1dHRvbjtyZXR1cm4gbnVsbD09ZS5wYWdlWCYmbnVsbCE9dC5jbGllbnRYJiYobj1lLnRhcmdl
dC5vd25lckRvY3VtZW50fHxvLHI9bi5kb2N1bWVudEVsZW1lbnQsaT1uLmJvZHksZS5wYWdlWD10
LmNsaWVudFgrKHImJnIuc2Nyb2xsTGVmdHx8aSYmaS5zY3JvbGxMZWZ0fHwwKS0ociYmci5jbGll
bnRMZWZ0fHxpJiZpLmNsaWVudExlZnR8fDApLGUucGFnZVk9dC5jbGllbnRZKyhyJiZyLnNjcm9s
bFRvcHx8aSYmaS5zY3JvbGxUb3B8fDApLShyJiZyLmNsaWVudFRvcHx8aSYmaS5jbGllbnRUb3B8
fDApKSxlLndoaWNofHxzPT09dW5kZWZpbmVkfHwoZS53aGljaD0xJnM/MToyJnM/Mzo0JnM/Mjow
KSxlfX0sZml4OmZ1bmN0aW9uKGUpe2lmKGVbeC5leHBhbmRvXSlyZXR1cm4gZTt2YXIgdCxuLHIs
aT1lLnR5cGUscz1lLGE9dGhpcy5maXhIb29rc1tpXTthfHwodGhpcy5maXhIb29rc1tpXT1hPXou
dGVzdChpKT90aGlzLm1vdXNlSG9va3M6SS50ZXN0KGkpP3RoaXMua2V5SG9va3M6e30pLHI9YS5w
cm9wcz90aGlzLnByb3BzLmNvbmNhdChhLnByb3BzKTp0aGlzLnByb3BzLGU9bmV3IHguRXZlbnQo
cyksdD1yLmxlbmd0aDt3aGlsZSh0LS0pbj1yW3RdLGVbbl09c1tuXTtyZXR1cm4gZS50YXJnZXR8
fChlLnRhcmdldD1vKSwzPT09ZS50YXJnZXQubm9kZVR5cGUmJihlLnRhcmdldD1lLnRhcmdldC5w
YXJlbnROb2RlKSxhLmZpbHRlcj9hLmZpbHRlcihlLHMpOmV9LHNwZWNpYWw6e2xvYWQ6e25vQnVi
YmxlOiEwfSxmb2N1czp7dHJpZ2dlcjpmdW5jdGlvbigpe3JldHVybiB0aGlzIT09VigpJiZ0aGlz
LmZvY3VzPyh0aGlzLmZvY3VzKCksITEpOnVuZGVmaW5lZH0sZGVsZWdhdGVUeXBlOiJmb2N1c2lu
In0sYmx1cjp7dHJpZ2dlcjpmdW5jdGlvbigpe3JldHVybiB0aGlzPT09VigpJiZ0aGlzLmJsdXI/
KHRoaXMuYmx1cigpLCExKTp1bmRlZmluZWR9LGRlbGVnYXRlVHlwZToiZm9jdXNvdXQifSxjbGlj
azp7dHJpZ2dlcjpmdW5jdGlvbigpe3JldHVybiJjaGVja2JveCI9PT10aGlzLnR5cGUmJnRoaXMu
Y2xpY2smJngubm9kZU5hbWUodGhpcywiaW5wdXQiKT8odGhpcy5jbGljaygpLCExKTp1bmRlZmlu
ZWR9LF9kZWZhdWx0OmZ1bmN0aW9uKGUpe3JldHVybiB4Lm5vZGVOYW1lKGUudGFyZ2V0LCJhIil9
fSxiZWZvcmV1bmxvYWQ6e3Bvc3REaXNwYXRjaDpmdW5jdGlvbihlKXtlLnJlc3VsdCE9PXVuZGVm
aW5lZCYmKGUub3JpZ2luYWxFdmVudC5yZXR1cm5WYWx1ZT1lLnJlc3VsdCl9fX0sc2ltdWxhdGU6
ZnVuY3Rpb24oZSx0LG4scil7dmFyIGk9eC5leHRlbmQobmV3IHguRXZlbnQsbix7dHlwZTplLGlz
U2ltdWxhdGVkOiEwLG9yaWdpbmFsRXZlbnQ6e319KTtyP3guZXZlbnQudHJpZ2dlcihpLG51bGws
dCk6eC5ldmVudC5kaXNwYXRjaC5jYWxsKHQsaSksaS5pc0RlZmF1bHRQcmV2ZW50ZWQoKSYmbi5w
cmV2ZW50RGVmYXVsdCgpfX0seC5yZW1vdmVFdmVudD1mdW5jdGlvbihlLHQsbil7ZS5yZW1vdmVF
dmVudExpc3RlbmVyJiZlLnJlbW92ZUV2ZW50TGlzdGVuZXIodCxuLCExKX0seC5FdmVudD1mdW5j
dGlvbihlLHQpe3JldHVybiB0aGlzIGluc3RhbmNlb2YgeC5FdmVudD8oZSYmZS50eXBlPyh0aGlz
Lm9yaWdpbmFsRXZlbnQ9ZSx0aGlzLnR5cGU9ZS50eXBlLHRoaXMuaXNEZWZhdWx0UHJldmVudGVk
PWUuZGVmYXVsdFByZXZlbnRlZHx8ZS5nZXRQcmV2ZW50RGVmYXVsdCYmZS5nZXRQcmV2ZW50RGVm
YXVsdCgpP1U6WSk6dGhpcy50eXBlPWUsdCYmeC5leHRlbmQodGhpcyx0KSx0aGlzLnRpbWVTdGFt
cD1lJiZlLnRpbWVTdGFtcHx8eC5ub3coKSx0aGlzW3guZXhwYW5kb109ITAsdW5kZWZpbmVkKTpu
ZXcgeC5FdmVudChlLHQpfSx4LkV2ZW50LnByb3RvdHlwZT17aXNEZWZhdWx0UHJldmVudGVkOlks
aXNQcm9wYWdhdGlvblN0b3BwZWQ6WSxpc0ltbWVkaWF0ZVByb3BhZ2F0aW9uU3RvcHBlZDpZLHBy
ZXZlbnREZWZhdWx0OmZ1bmN0aW9uKCl7dmFyIGU9dGhpcy5vcmlnaW5hbEV2ZW50O3RoaXMuaXNE
ZWZhdWx0UHJldmVudGVkPVUsZSYmZS5wcmV2ZW50RGVmYXVsdCYmZS5wcmV2ZW50RGVmYXVsdCgp
fSxzdG9wUHJvcGFnYXRpb246ZnVuY3Rpb24oKXt2YXIgZT10aGlzLm9yaWdpbmFsRXZlbnQ7dGhp
cy5pc1Byb3BhZ2F0aW9uU3RvcHBlZD1VLGUmJmUuc3RvcFByb3BhZ2F0aW9uJiZlLnN0b3BQcm9w
YWdhdGlvbigpfSxzdG9wSW1tZWRpYXRlUHJvcGFnYXRpb246ZnVuY3Rpb24oKXt0aGlzLmlzSW1t
ZWRpYXRlUHJvcGFnYXRpb25TdG9wcGVkPVUsdGhpcy5zdG9wUHJvcGFnYXRpb24oKX19LHguZWFj
aCh7bW91c2VlbnRlcjoibW91c2VvdmVyIixtb3VzZWxlYXZlOiJtb3VzZW91dCJ9LGZ1bmN0aW9u
KGUsdCl7eC5ldmVudC5zcGVjaWFsW2VdPXtkZWxlZ2F0ZVR5cGU6dCxiaW5kVHlwZTp0LGhhbmRs
ZTpmdW5jdGlvbihlKXt2YXIgbixyPXRoaXMsaT1lLnJlbGF0ZWRUYXJnZXQsbz1lLmhhbmRsZU9i
ajtyZXR1cm4oIWl8fGkhPT1yJiYheC5jb250YWlucyhyLGkpKSYmKGUudHlwZT1vLm9yaWdUeXBl
LG49by5oYW5kbGVyLmFwcGx5KHRoaXMsYXJndW1lbnRzKSxlLnR5cGU9dCksbn19fSkseC5zdXBw
b3J0LmZvY3VzaW5CdWJibGVzfHx4LmVhY2goe2ZvY3VzOiJmb2N1c2luIixibHVyOiJmb2N1c291
dCJ9LGZ1bmN0aW9uKGUsdCl7dmFyIG49MCxyPWZ1bmN0aW9uKGUpe3guZXZlbnQuc2ltdWxhdGUo
dCxlLnRhcmdldCx4LmV2ZW50LmZpeChlKSwhMCl9O3guZXZlbnQuc3BlY2lhbFt0XT17c2V0dXA6
ZnVuY3Rpb24oKXswPT09bisrJiZvLmFkZEV2ZW50TGlzdGVuZXIoZSxyLCEwKX0sdGVhcmRvd246
ZnVuY3Rpb24oKXswPT09LS1uJiZvLnJlbW92ZUV2ZW50TGlzdGVuZXIoZSxyLCEwKX19fSkseC5m
bi5leHRlbmQoe29uOmZ1bmN0aW9uKGUsdCxuLHIsaSl7dmFyIG8scztpZigib2JqZWN0Ij09dHlw
ZW9mIGUpeyJzdHJpbmciIT10eXBlb2YgdCYmKG49bnx8dCx0PXVuZGVmaW5lZCk7Zm9yKHMgaW4g
ZSl0aGlzLm9uKHMsdCxuLGVbc10saSk7cmV0dXJuIHRoaXN9aWYobnVsbD09biYmbnVsbD09cj8o
cj10LG49dD11bmRlZmluZWQpOm51bGw9PXImJigic3RyaW5nIj09dHlwZW9mIHQ/KHI9bixuPXVu
ZGVmaW5lZCk6KHI9bixuPXQsdD11bmRlZmluZWQpKSxyPT09ITEpcj1ZO2Vsc2UgaWYoIXIpcmV0
dXJuIHRoaXM7cmV0dXJuIDE9PT1pJiYobz1yLHI9ZnVuY3Rpb24oZSl7cmV0dXJuIHgoKS5vZmYo
ZSksby5hcHBseSh0aGlzLGFyZ3VtZW50cyl9LHIuZ3VpZD1vLmd1aWR8fChvLmd1aWQ9eC5ndWlk
KyspKSx0aGlzLmVhY2goZnVuY3Rpb24oKXt4LmV2ZW50LmFkZCh0aGlzLGUscixuLHQpfSl9LG9u
ZTpmdW5jdGlvbihlLHQsbixyKXtyZXR1cm4gdGhpcy5vbihlLHQsbixyLDEpfSxvZmY6ZnVuY3Rp
b24oZSx0LG4pe3ZhciByLGk7aWYoZSYmZS5wcmV2ZW50RGVmYXVsdCYmZS5oYW5kbGVPYmopcmV0
dXJuIHI9ZS5oYW5kbGVPYmoseChlLmRlbGVnYXRlVGFyZ2V0KS5vZmYoci5uYW1lc3BhY2U/ci5v
cmlnVHlwZSsiLiIrci5uYW1lc3BhY2U6ci5vcmlnVHlwZSxyLnNlbGVjdG9yLHIuaGFuZGxlciks
dGhpcztpZigib2JqZWN0Ij09dHlwZW9mIGUpe2ZvcihpIGluIGUpdGhpcy5vZmYoaSx0LGVbaV0p
O3JldHVybiB0aGlzfXJldHVybih0PT09ITF8fCJmdW5jdGlvbiI9PXR5cGVvZiB0KSYmKG49dCx0
PXVuZGVmaW5lZCksbj09PSExJiYobj1ZKSx0aGlzLmVhY2goZnVuY3Rpb24oKXt4LmV2ZW50LnJl
bW92ZSh0aGlzLGUsbix0KX0pfSx0cmlnZ2VyOmZ1bmN0aW9uKGUsdCl7cmV0dXJuIHRoaXMuZWFj
aChmdW5jdGlvbigpe3guZXZlbnQudHJpZ2dlcihlLHQsdGhpcyl9KX0sdHJpZ2dlckhhbmRsZXI6
ZnVuY3Rpb24oZSx0KXt2YXIgbj10aGlzWzBdO3JldHVybiBuP3guZXZlbnQudHJpZ2dlcihlLHQs
biwhMCk6dW5kZWZpbmVkfX0pO3ZhciBHPS9eLlteOiNcW1wuLF0qJC8sSj0vXig/OnBhcmVudHN8
cHJldig/OlVudGlsfEFsbCkpLyxRPXguZXhwci5tYXRjaC5uZWVkc0NvbnRleHQsSz17Y2hpbGRy
ZW46ITAsY29udGVudHM6ITAsbmV4dDohMCxwcmV2OiEwfTt4LmZuLmV4dGVuZCh7ZmluZDpmdW5j
dGlvbihlKXt2YXIgdCxuPVtdLHI9dGhpcyxpPXIubGVuZ3RoO2lmKCJzdHJpbmciIT10eXBlb2Yg
ZSlyZXR1cm4gdGhpcy5wdXNoU3RhY2soeChlKS5maWx0ZXIoZnVuY3Rpb24oKXtmb3IodD0wO2k+
dDt0KyspaWYoeC5jb250YWlucyhyW3RdLHRoaXMpKXJldHVybiEwfSkpO2Zvcih0PTA7aT50O3Qr
Kyl4LmZpbmQoZSxyW3RdLG4pO3JldHVybiBuPXRoaXMucHVzaFN0YWNrKGk+MT94LnVuaXF1ZShu
KTpuKSxuLnNlbGVjdG9yPXRoaXMuc2VsZWN0b3I/dGhpcy5zZWxlY3RvcisiICIrZTplLG59LGhh
czpmdW5jdGlvbihlKXt2YXIgdD14KGUsdGhpcyksbj10Lmxlbmd0aDtyZXR1cm4gdGhpcy5maWx0
ZXIoZnVuY3Rpb24oKXt2YXIgZT0wO2Zvcig7bj5lO2UrKylpZih4LmNvbnRhaW5zKHRoaXMsdFtl
XSkpcmV0dXJuITB9KX0sbm90OmZ1bmN0aW9uKGUpe3JldHVybiB0aGlzLnB1c2hTdGFjayhldCh0
aGlzLGV8fFtdLCEwKSl9LGZpbHRlcjpmdW5jdGlvbihlKXtyZXR1cm4gdGhpcy5wdXNoU3RhY2so
ZXQodGhpcyxlfHxbXSwhMSkpfSxpczpmdW5jdGlvbihlKXtyZXR1cm4hIWV0KHRoaXMsInN0cmlu
ZyI9PXR5cGVvZiBlJiZRLnRlc3QoZSk/eChlKTplfHxbXSwhMSkubGVuZ3RofSxjbG9zZXN0OmZ1
bmN0aW9uKGUsdCl7dmFyIG4scj0wLGk9dGhpcy5sZW5ndGgsbz1bXSxzPVEudGVzdChlKXx8InN0
cmluZyIhPXR5cGVvZiBlP3goZSx0fHx0aGlzLmNvbnRleHQpOjA7Zm9yKDtpPnI7cisrKWZvcihu
PXRoaXNbcl07biYmbiE9PXQ7bj1uLnBhcmVudE5vZGUpaWYoMTE+bi5ub2RlVHlwZSYmKHM/cy5p
bmRleChuKT4tMToxPT09bi5ub2RlVHlwZSYmeC5maW5kLm1hdGNoZXNTZWxlY3RvcihuLGUpKSl7
bj1vLnB1c2gobik7YnJlYWt9cmV0dXJuIHRoaXMucHVzaFN0YWNrKG8ubGVuZ3RoPjE/eC51bmlx
dWUobyk6byl9LGluZGV4OmZ1bmN0aW9uKGUpe3JldHVybiBlPyJzdHJpbmciPT10eXBlb2YgZT9n
LmNhbGwoeChlKSx0aGlzWzBdKTpnLmNhbGwodGhpcyxlLmpxdWVyeT9lWzBdOmUpOnRoaXNbMF0m
JnRoaXNbMF0ucGFyZW50Tm9kZT90aGlzLmZpcnN0KCkucHJldkFsbCgpLmxlbmd0aDotMX0sYWRk
OmZ1bmN0aW9uKGUsdCl7dmFyIG49InN0cmluZyI9PXR5cGVvZiBlP3goZSx0KTp4Lm1ha2VBcnJh
eShlJiZlLm5vZGVUeXBlP1tlXTplKSxyPXgubWVyZ2UodGhpcy5nZXQoKSxuKTtyZXR1cm4gdGhp
cy5wdXNoU3RhY2soeC51bmlxdWUocikpfSxhZGRCYWNrOmZ1bmN0aW9uKGUpe3JldHVybiB0aGlz
LmFkZChudWxsPT1lP3RoaXMucHJldk9iamVjdDp0aGlzLnByZXZPYmplY3QuZmlsdGVyKGUpKX19
KTtmdW5jdGlvbiBaKGUsdCl7d2hpbGUoKGU9ZVt0XSkmJjEhPT1lLm5vZGVUeXBlKTtyZXR1cm4g
ZX14LmVhY2goe3BhcmVudDpmdW5jdGlvbihlKXt2YXIgdD1lLnBhcmVudE5vZGU7cmV0dXJuIHQm
JjExIT09dC5ub2RlVHlwZT90Om51bGx9LHBhcmVudHM6ZnVuY3Rpb24oZSl7cmV0dXJuIHguZGly
KGUsInBhcmVudE5vZGUiKX0scGFyZW50c1VudGlsOmZ1bmN0aW9uKGUsdCxuKXtyZXR1cm4geC5k
aXIoZSwicGFyZW50Tm9kZSIsbil9LG5leHQ6ZnVuY3Rpb24oZSl7cmV0dXJuIFooZSwibmV4dFNp
YmxpbmciKX0scHJldjpmdW5jdGlvbihlKXtyZXR1cm4gWihlLCJwcmV2aW91c1NpYmxpbmciKX0s
bmV4dEFsbDpmdW5jdGlvbihlKXtyZXR1cm4geC5kaXIoZSwibmV4dFNpYmxpbmciKX0scHJldkFs
bDpmdW5jdGlvbihlKXtyZXR1cm4geC5kaXIoZSwicHJldmlvdXNTaWJsaW5nIil9LG5leHRVbnRp
bDpmdW5jdGlvbihlLHQsbil7cmV0dXJuIHguZGlyKGUsIm5leHRTaWJsaW5nIixuKX0scHJldlVu
dGlsOmZ1bmN0aW9uKGUsdCxuKXtyZXR1cm4geC5kaXIoZSwicHJldmlvdXNTaWJsaW5nIixuKX0s
c2libGluZ3M6ZnVuY3Rpb24oZSl7cmV0dXJuIHguc2libGluZygoZS5wYXJlbnROb2RlfHx7fSku
Zmlyc3RDaGlsZCxlKX0sY2hpbGRyZW46ZnVuY3Rpb24oZSl7cmV0dXJuIHguc2libGluZyhlLmZp
cnN0Q2hpbGQpfSxjb250ZW50czpmdW5jdGlvbihlKXtyZXR1cm4geC5ub2RlTmFtZShlLCJpZnJh
bWUiKT9lLmNvbnRlbnREb2N1bWVudHx8ZS5jb250ZW50V2luZG93LmRvY3VtZW50OngubWVyZ2Uo
W10sZS5jaGlsZE5vZGVzKX19LGZ1bmN0aW9uKGUsdCl7eC5mbltlXT1mdW5jdGlvbihuLHIpe3Zh
ciBpPXgubWFwKHRoaXMsdCxuKTtyZXR1cm4iVW50aWwiIT09ZS5zbGljZSgtNSkmJihyPW4pLHIm
JiJzdHJpbmciPT10eXBlb2YgciYmKGk9eC5maWx0ZXIocixpKSksdGhpcy5sZW5ndGg+MSYmKEtb
ZV18fHgudW5pcXVlKGkpLEoudGVzdChlKSYmaS5yZXZlcnNlKCkpLHRoaXMucHVzaFN0YWNrKGkp
fX0pLHguZXh0ZW5kKHtmaWx0ZXI6ZnVuY3Rpb24oZSx0LG4pe3ZhciByPXRbMF07cmV0dXJuIG4m
JihlPSI6bm90KCIrZSsiKSIpLDE9PT10Lmxlbmd0aCYmMT09PXIubm9kZVR5cGU/eC5maW5kLm1h
dGNoZXNTZWxlY3RvcihyLGUpP1tyXTpbXTp4LmZpbmQubWF0Y2hlcyhlLHguZ3JlcCh0LGZ1bmN0
aW9uKGUpe3JldHVybiAxPT09ZS5ub2RlVHlwZX0pKX0sZGlyOmZ1bmN0aW9uKGUsdCxuKXt2YXIg
cj1bXSxpPW4hPT11bmRlZmluZWQ7d2hpbGUoKGU9ZVt0XSkmJjkhPT1lLm5vZGVUeXBlKWlmKDE9
PT1lLm5vZGVUeXBlKXtpZihpJiZ4KGUpLmlzKG4pKWJyZWFrO3IucHVzaChlKX1yZXR1cm4gcn0s
c2libGluZzpmdW5jdGlvbihlLHQpe3ZhciBuPVtdO2Zvcig7ZTtlPWUubmV4dFNpYmxpbmcpMT09
PWUubm9kZVR5cGUmJmUhPT10JiZuLnB1c2goZSk7cmV0dXJuIG59fSk7ZnVuY3Rpb24gZXQoZSx0
LG4pe2lmKHguaXNGdW5jdGlvbih0KSlyZXR1cm4geC5ncmVwKGUsZnVuY3Rpb24oZSxyKXtyZXR1
cm4hIXQuY2FsbChlLHIsZSkhPT1ufSk7aWYodC5ub2RlVHlwZSlyZXR1cm4geC5ncmVwKGUsZnVu
Y3Rpb24oZSl7cmV0dXJuIGU9PT10IT09bn0pO2lmKCJzdHJpbmciPT10eXBlb2YgdCl7aWYoRy50
ZXN0KHQpKXJldHVybiB4LmZpbHRlcih0LGUsbik7dD14LmZpbHRlcih0LGUpfXJldHVybiB4Lmdy
ZXAoZSxmdW5jdGlvbihlKXtyZXR1cm4gZy5jYWxsKHQsZSk+PTAhPT1ufSl9dmFyIHR0PS88KD8h
YXJlYXxicnxjb2x8ZW1iZWR8aHJ8aW1nfGlucHV0fGxpbmt8bWV0YXxwYXJhbSkoKFtcdzpdKylb
Xj5dKilcLz4vZ2ksbnQ9LzwoW1x3Ol0rKS8scnQ9Lzx8JiM/XHcrOy8saXQ9LzwoPzpzY3JpcHR8
c3R5bGV8bGluaykvaSxvdD0vXig/OmNoZWNrYm94fHJhZGlvKSQvaSxzdD0vY2hlY2tlZFxzKig/
OltePV18PVxzKi5jaGVja2VkLikvaSxhdD0vXiR8XC8oPzpqYXZhfGVjbWEpc2NyaXB0L2ksdXQ9
L150cnVlXC8oLiopLyxsdD0vXlxzKjwhKD86XFtDREFUQVxbfC0tKXwoPzpcXVxdfC0tKT5ccyok
L2csY3Q9e29wdGlvbjpbMSwiPHNlbGVjdCBtdWx0aXBsZT0nbXVsdGlwbGUnPiIsIjwvc2VsZWN0
PiJdLHRoZWFkOlsxLCI8dGFibGU+IiwiPC90YWJsZT4iXSxjb2w6WzIsIjx0YWJsZT48Y29sZ3Jv
dXA+IiwiPC9jb2xncm91cD48L3RhYmxlPiJdLHRyOlsyLCI8dGFibGU+PHRib2R5PiIsIjwvdGJv
ZHk+PC90YWJsZT4iXSx0ZDpbMywiPHRhYmxlPjx0Ym9keT48dHI+IiwiPC90cj48L3Rib2R5Pjwv
dGFibGU+Il0sX2RlZmF1bHQ6WzAsIiIsIiJdfTtjdC5vcHRncm91cD1jdC5vcHRpb24sY3QudGJv
ZHk9Y3QudGZvb3Q9Y3QuY29sZ3JvdXA9Y3QuY2FwdGlvbj1jdC50aGVhZCxjdC50aD1jdC50ZCx4
LmZuLmV4dGVuZCh7dGV4dDpmdW5jdGlvbihlKXtyZXR1cm4geC5hY2Nlc3ModGhpcyxmdW5jdGlv
bihlKXtyZXR1cm4gZT09PXVuZGVmaW5lZD94LnRleHQodGhpcyk6dGhpcy5lbXB0eSgpLmFwcGVu
ZCgodGhpc1swXSYmdGhpc1swXS5vd25lckRvY3VtZW50fHxvKS5jcmVhdGVUZXh0Tm9kZShlKSl9
LG51bGwsZSxhcmd1bWVudHMubGVuZ3RoKX0sYXBwZW5kOmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMu
ZG9tTWFuaXAoYXJndW1lbnRzLGZ1bmN0aW9uKGUpe2lmKDE9PT10aGlzLm5vZGVUeXBlfHwxMT09
PXRoaXMubm9kZVR5cGV8fDk9PT10aGlzLm5vZGVUeXBlKXt2YXIgdD1mdCh0aGlzLGUpO3QuYXBw
ZW5kQ2hpbGQoZSl9fSl9LHByZXBlbmQ6ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5kb21NYW5pcChh
cmd1bWVudHMsZnVuY3Rpb24oZSl7aWYoMT09PXRoaXMubm9kZVR5cGV8fDExPT09dGhpcy5ub2Rl
VHlwZXx8OT09PXRoaXMubm9kZVR5cGUpe3ZhciB0PWZ0KHRoaXMsZSk7dC5pbnNlcnRCZWZvcmUo
ZSx0LmZpcnN0Q2hpbGQpfX0pfSxiZWZvcmU6ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5kb21NYW5p
cChhcmd1bWVudHMsZnVuY3Rpb24oZSl7dGhpcy5wYXJlbnROb2RlJiZ0aGlzLnBhcmVudE5vZGUu
aW5zZXJ0QmVmb3JlKGUsdGhpcyl9KX0sYWZ0ZXI6ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5kb21N
YW5pcChhcmd1bWVudHMsZnVuY3Rpb24oZSl7dGhpcy5wYXJlbnROb2RlJiZ0aGlzLnBhcmVudE5v
ZGUuaW5zZXJ0QmVmb3JlKGUsdGhpcy5uZXh0U2libGluZyl9KX0scmVtb3ZlOmZ1bmN0aW9uKGUs
dCl7dmFyIG4scj1lP3guZmlsdGVyKGUsdGhpcyk6dGhpcyxpPTA7Zm9yKDtudWxsIT0obj1yW2ld
KTtpKyspdHx8MSE9PW4ubm9kZVR5cGV8fHguY2xlYW5EYXRhKG10KG4pKSxuLnBhcmVudE5vZGUm
Jih0JiZ4LmNvbnRhaW5zKG4ub3duZXJEb2N1bWVudCxuKSYmZHQobXQobiwic2NyaXB0IikpLG4u
cGFyZW50Tm9kZS5yZW1vdmVDaGlsZChuKSk7cmV0dXJuIHRoaXN9LGVtcHR5OmZ1bmN0aW9uKCl7
dmFyIGUsdD0wO2Zvcig7bnVsbCE9KGU9dGhpc1t0XSk7dCsrKTE9PT1lLm5vZGVUeXBlJiYoeC5j
bGVhbkRhdGEobXQoZSwhMSkpLGUudGV4dENvbnRlbnQ9IiIpO3JldHVybiB0aGlzfSxjbG9uZTpm
dW5jdGlvbihlLHQpe3JldHVybiBlPW51bGw9PWU/ITE6ZSx0PW51bGw9PXQ/ZTp0LHRoaXMubWFw
KGZ1bmN0aW9uKCl7cmV0dXJuIHguY2xvbmUodGhpcyxlLHQpfSl9LGh0bWw6ZnVuY3Rpb24oZSl7
cmV0dXJuIHguYWNjZXNzKHRoaXMsZnVuY3Rpb24oZSl7dmFyIHQ9dGhpc1swXXx8e30sbj0wLHI9
dGhpcy5sZW5ndGg7aWYoZT09PXVuZGVmaW5lZCYmMT09PXQubm9kZVR5cGUpcmV0dXJuIHQuaW5u
ZXJIVE1MO2lmKCJzdHJpbmciPT10eXBlb2YgZSYmIWl0LnRlc3QoZSkmJiFjdFsobnQuZXhlYyhl
KXx8WyIiLCIiXSlbMV0udG9Mb3dlckNhc2UoKV0pe2U9ZS5yZXBsYWNlKHR0LCI8JDE+PC8kMj4i
KTt0cnl7Zm9yKDtyPm47bisrKXQ9dGhpc1tuXXx8e30sMT09PXQubm9kZVR5cGUmJih4LmNsZWFu
RGF0YShtdCh0LCExKSksdC5pbm5lckhUTUw9ZSk7dD0wfWNhdGNoKGkpe319dCYmdGhpcy5lbXB0
eSgpLmFwcGVuZChlKX0sbnVsbCxlLGFyZ3VtZW50cy5sZW5ndGgpfSxyZXBsYWNlV2l0aDpmdW5j
dGlvbigpe3ZhciBlPXgubWFwKHRoaXMsZnVuY3Rpb24oZSl7cmV0dXJuW2UubmV4dFNpYmxpbmcs
ZS5wYXJlbnROb2RlXX0pLHQ9MDtyZXR1cm4gdGhpcy5kb21NYW5pcChhcmd1bWVudHMsZnVuY3Rp
b24obil7dmFyIHI9ZVt0KytdLGk9ZVt0KytdO2kmJihyJiZyLnBhcmVudE5vZGUhPT1pJiYocj10
aGlzLm5leHRTaWJsaW5nKSx4KHRoaXMpLnJlbW92ZSgpLGkuaW5zZXJ0QmVmb3JlKG4scikpfSwh
MCksdD90aGlzOnRoaXMucmVtb3ZlKCl9LGRldGFjaDpmdW5jdGlvbihlKXtyZXR1cm4gdGhpcy5y
ZW1vdmUoZSwhMCl9LGRvbU1hbmlwOmZ1bmN0aW9uKGUsdCxuKXtlPXAuYXBwbHkoW10sZSk7dmFy
IHIsaSxvLHMsYSx1LGw9MCxjPXRoaXMubGVuZ3RoLGY9dGhpcyxoPWMtMSxkPWVbMF0sZz14Lmlz
RnVuY3Rpb24oZCk7aWYoZ3x8ISgxPj1jfHwic3RyaW5nIiE9dHlwZW9mIGR8fHguc3VwcG9ydC5j
aGVja0Nsb25lKSYmc3QudGVzdChkKSlyZXR1cm4gdGhpcy5lYWNoKGZ1bmN0aW9uKHIpe3ZhciBp
PWYuZXEocik7ZyYmKGVbMF09ZC5jYWxsKHRoaXMscixpLmh0bWwoKSkpLGkuZG9tTWFuaXAoZSx0
LG4pfSk7aWYoYyYmKHI9eC5idWlsZEZyYWdtZW50KGUsdGhpc1swXS5vd25lckRvY3VtZW50LCEx
LCFuJiZ0aGlzKSxpPXIuZmlyc3RDaGlsZCwxPT09ci5jaGlsZE5vZGVzLmxlbmd0aCYmKHI9aSks
aSkpe2ZvcihvPXgubWFwKG10KHIsInNjcmlwdCIpLHB0KSxzPW8ubGVuZ3RoO2M+bDtsKyspYT1y
LGwhPT1oJiYoYT14LmNsb25lKGEsITAsITApLHMmJngubWVyZ2UobyxtdChhLCJzY3JpcHQiKSkp
LHQuY2FsbCh0aGlzW2xdLGEsbCk7aWYocylmb3IodT1vW28ubGVuZ3RoLTFdLm93bmVyRG9jdW1l
bnQseC5tYXAobyxodCksbD0wO3M+bDtsKyspYT1vW2xdLGF0LnRlc3QoYS50eXBlfHwiIikmJiFI
LmFjY2VzcyhhLCJnbG9iYWxFdmFsIikmJnguY29udGFpbnModSxhKSYmKGEuc3JjP3guX2V2YWxV
cmwoYS5zcmMpOnguZ2xvYmFsRXZhbChhLnRleHRDb250ZW50LnJlcGxhY2UobHQsIiIpKSl9cmV0
dXJuIHRoaXN9fSkseC5lYWNoKHthcHBlbmRUbzoiYXBwZW5kIixwcmVwZW5kVG86InByZXBlbmQi
LGluc2VydEJlZm9yZToiYmVmb3JlIixpbnNlcnRBZnRlcjoiYWZ0ZXIiLHJlcGxhY2VBbGw6InJl
cGxhY2VXaXRoIn0sZnVuY3Rpb24oZSx0KXt4LmZuW2VdPWZ1bmN0aW9uKGUpe3ZhciBuLHI9W10s
aT14KGUpLG89aS5sZW5ndGgtMSxzPTA7Zm9yKDtvPj1zO3MrKyluPXM9PT1vP3RoaXM6dGhpcy5j
bG9uZSghMCkseChpW3NdKVt0XShuKSxoLmFwcGx5KHIsbi5nZXQoKSk7cmV0dXJuIHRoaXMucHVz
aFN0YWNrKHIpfX0pLHguZXh0ZW5kKHtjbG9uZTpmdW5jdGlvbihlLHQsbil7dmFyIHIsaSxvLHMs
YT1lLmNsb25lTm9kZSghMCksdT14LmNvbnRhaW5zKGUub3duZXJEb2N1bWVudCxlKTtpZighKHgu
c3VwcG9ydC5ub0Nsb25lQ2hlY2tlZHx8MSE9PWUubm9kZVR5cGUmJjExIT09ZS5ub2RlVHlwZXx8
eC5pc1hNTERvYyhlKSkpZm9yKHM9bXQoYSksbz1tdChlKSxyPTAsaT1vLmxlbmd0aDtpPnI7cisr
KXl0KG9bcl0sc1tyXSk7aWYodClpZihuKWZvcihvPW98fG10KGUpLHM9c3x8bXQoYSkscj0wLGk9
by5sZW5ndGg7aT5yO3IrKylndChvW3JdLHNbcl0pO2Vsc2UgZ3QoZSxhKTtyZXR1cm4gcz1tdChh
LCJzY3JpcHQiKSxzLmxlbmd0aD4wJiZkdChzLCF1JiZtdChlLCJzY3JpcHQiKSksYX0sYnVpbGRG
cmFnbWVudDpmdW5jdGlvbihlLHQsbixyKXt2YXIgaSxvLHMsYSx1LGwsYz0wLGY9ZS5sZW5ndGgs
cD10LmNyZWF0ZURvY3VtZW50RnJhZ21lbnQoKSxoPVtdO2Zvcig7Zj5jO2MrKylpZihpPWVbY10s
aXx8MD09PWkpaWYoIm9iamVjdCI9PT14LnR5cGUoaSkpeC5tZXJnZShoLGkubm9kZVR5cGU/W2ld
OmkpO2Vsc2UgaWYocnQudGVzdChpKSl7bz1vfHxwLmFwcGVuZENoaWxkKHQuY3JlYXRlRWxlbWVu
dCgiZGl2IikpLHM9KG50LmV4ZWMoaSl8fFsiIiwiIl0pWzFdLnRvTG93ZXJDYXNlKCksYT1jdFtz
XXx8Y3QuX2RlZmF1bHQsby5pbm5lckhUTUw9YVsxXStpLnJlcGxhY2UodHQsIjwkMT48LyQyPiIp
K2FbMl0sbD1hWzBdO3doaWxlKGwtLSlvPW8uZmlyc3RDaGlsZDt4Lm1lcmdlKGgsby5jaGlsZE5v
ZGVzKSxvPXAuZmlyc3RDaGlsZCxvLnRleHRDb250ZW50PSIifWVsc2UgaC5wdXNoKHQuY3JlYXRl
VGV4dE5vZGUoaSkpO3AudGV4dENvbnRlbnQ9IiIsYz0wO3doaWxlKGk9aFtjKytdKWlmKCghcnx8
LTE9PT14LmluQXJyYXkoaSxyKSkmJih1PXguY29udGFpbnMoaS5vd25lckRvY3VtZW50LGkpLG89
bXQocC5hcHBlbmRDaGlsZChpKSwic2NyaXB0IiksdSYmZHQobyksbikpe2w9MDt3aGlsZShpPW9b
bCsrXSlhdC50ZXN0KGkudHlwZXx8IiIpJiZuLnB1c2goaSl9cmV0dXJuIHB9LGNsZWFuRGF0YTpm
dW5jdGlvbihlKXt2YXIgdCxuLHIsaSxvLHMsYT14LmV2ZW50LnNwZWNpYWwsdT0wO2Zvcig7KG49
ZVt1XSkhPT11bmRlZmluZWQ7dSsrKXtpZihGLmFjY2VwdHMobikmJihvPW5bSC5leHBhbmRvXSxv
JiYodD1ILmNhY2hlW29dKSkpe2lmKHI9T2JqZWN0LmtleXModC5ldmVudHN8fHt9KSxyLmxlbmd0
aClmb3Iocz0wOyhpPXJbc10pIT09dW5kZWZpbmVkO3MrKylhW2ldP3guZXZlbnQucmVtb3ZlKG4s
aSk6eC5yZW1vdmVFdmVudChuLGksdC5oYW5kbGUpO0guY2FjaGVbb10mJmRlbGV0ZSBILmNhY2hl
W29dfWRlbGV0ZSBMLmNhY2hlW25bTC5leHBhbmRvXV19fSxfZXZhbFVybDpmdW5jdGlvbihlKXty
ZXR1cm4geC5hamF4KHt1cmw6ZSx0eXBlOiJHRVQiLGRhdGFUeXBlOiJzY3JpcHQiLGFzeW5jOiEx
LGdsb2JhbDohMSwidGhyb3dzIjohMH0pfX0pO2Z1bmN0aW9uIGZ0KGUsdCl7cmV0dXJuIHgubm9k
ZU5hbWUoZSwidGFibGUiKSYmeC5ub2RlTmFtZSgxPT09dC5ub2RlVHlwZT90OnQuZmlyc3RDaGls
ZCwidHIiKT9lLmdldEVsZW1lbnRzQnlUYWdOYW1lKCJ0Ym9keSIpWzBdfHxlLmFwcGVuZENoaWxk
KGUub3duZXJEb2N1bWVudC5jcmVhdGVFbGVtZW50KCJ0Ym9keSIpKTplfWZ1bmN0aW9uIHB0KGUp
e3JldHVybiBlLnR5cGU9KG51bGwhPT1lLmdldEF0dHJpYnV0ZSgidHlwZSIpKSsiLyIrZS50eXBl
LGV9ZnVuY3Rpb24gaHQoZSl7dmFyIHQ9dXQuZXhlYyhlLnR5cGUpO3JldHVybiB0P2UudHlwZT10
WzFdOmUucmVtb3ZlQXR0cmlidXRlKCJ0eXBlIiksZX1mdW5jdGlvbiBkdChlLHQpe3ZhciBuPWUu
bGVuZ3RoLHI9MDtmb3IoO24+cjtyKyspSC5zZXQoZVtyXSwiZ2xvYmFsRXZhbCIsIXR8fEguZ2V0
KHRbcl0sImdsb2JhbEV2YWwiKSl9ZnVuY3Rpb24gZ3QoZSx0KXt2YXIgbixyLGksbyxzLGEsdSxs
O2lmKDE9PT10Lm5vZGVUeXBlKXtpZihILmhhc0RhdGEoZSkmJihvPUguYWNjZXNzKGUpLHM9SC5z
ZXQodCxvKSxsPW8uZXZlbnRzKSl7ZGVsZXRlIHMuaGFuZGxlLHMuZXZlbnRzPXt9O2ZvcihpIGlu
IGwpZm9yKG49MCxyPWxbaV0ubGVuZ3RoO3I+bjtuKyspeC5ldmVudC5hZGQodCxpLGxbaV1bbl0p
fUwuaGFzRGF0YShlKSYmKGE9TC5hY2Nlc3MoZSksdT14LmV4dGVuZCh7fSxhKSxMLnNldCh0LHUp
KX19ZnVuY3Rpb24gbXQoZSx0KXt2YXIgbj1lLmdldEVsZW1lbnRzQnlUYWdOYW1lP2UuZ2V0RWxl
bWVudHNCeVRhZ05hbWUodHx8IioiKTplLnF1ZXJ5U2VsZWN0b3JBbGw/ZS5xdWVyeVNlbGVjdG9y
QWxsKHR8fCIqIik6W107cmV0dXJuIHQ9PT11bmRlZmluZWR8fHQmJngubm9kZU5hbWUoZSx0KT94
Lm1lcmdlKFtlXSxuKTpufWZ1bmN0aW9uIHl0KGUsdCl7dmFyIG49dC5ub2RlTmFtZS50b0xvd2Vy
Q2FzZSgpOyJpbnB1dCI9PT1uJiZvdC50ZXN0KGUudHlwZSk/dC5jaGVja2VkPWUuY2hlY2tlZDoo
ImlucHV0Ij09PW58fCJ0ZXh0YXJlYSI9PT1uKSYmKHQuZGVmYXVsdFZhbHVlPWUuZGVmYXVsdFZh
bHVlKX14LmZuLmV4dGVuZCh7d3JhcEFsbDpmdW5jdGlvbihlKXt2YXIgdDtyZXR1cm4geC5pc0Z1
bmN0aW9uKGUpP3RoaXMuZWFjaChmdW5jdGlvbih0KXt4KHRoaXMpLndyYXBBbGwoZS5jYWxsKHRo
aXMsdCkpfSk6KHRoaXNbMF0mJih0PXgoZSx0aGlzWzBdLm93bmVyRG9jdW1lbnQpLmVxKDApLmNs
b25lKCEwKSx0aGlzWzBdLnBhcmVudE5vZGUmJnQuaW5zZXJ0QmVmb3JlKHRoaXNbMF0pLHQubWFw
KGZ1bmN0aW9uKCl7dmFyIGU9dGhpczt3aGlsZShlLmZpcnN0RWxlbWVudENoaWxkKWU9ZS5maXJz
dEVsZW1lbnRDaGlsZDtyZXR1cm4gZX0pLmFwcGVuZCh0aGlzKSksdGhpcyl9LHdyYXBJbm5lcjpm
dW5jdGlvbihlKXtyZXR1cm4geC5pc0Z1bmN0aW9uKGUpP3RoaXMuZWFjaChmdW5jdGlvbih0KXt4
KHRoaXMpLndyYXBJbm5lcihlLmNhbGwodGhpcyx0KSl9KTp0aGlzLmVhY2goZnVuY3Rpb24oKXt2
YXIgdD14KHRoaXMpLG49dC5jb250ZW50cygpO24ubGVuZ3RoP24ud3JhcEFsbChlKTp0LmFwcGVu
ZChlKX0pfSx3cmFwOmZ1bmN0aW9uKGUpe3ZhciB0PXguaXNGdW5jdGlvbihlKTtyZXR1cm4gdGhp
cy5lYWNoKGZ1bmN0aW9uKG4pe3godGhpcykud3JhcEFsbCh0P2UuY2FsbCh0aGlzLG4pOmUpfSl9
LHVud3JhcDpmdW5jdGlvbigpe3JldHVybiB0aGlzLnBhcmVudCgpLmVhY2goZnVuY3Rpb24oKXt4
Lm5vZGVOYW1lKHRoaXMsImJvZHkiKXx8eCh0aGlzKS5yZXBsYWNlV2l0aCh0aGlzLmNoaWxkTm9k
ZXMpfSkuZW5kKCl9fSk7dmFyIHZ0LHh0LGJ0PS9eKG5vbmV8dGFibGUoPyEtY1tlYV0pLispLyx3
dD0vXm1hcmdpbi8sVHQ9UmVnRXhwKCJeKCIrYisiKSguKikkIiwiaSIpLEN0PVJlZ0V4cCgiXigi
K2IrIikoPyFweClbYS16JV0rJCIsImkiKSxrdD1SZWdFeHAoIl4oWystXSk9KCIrYisiKSIsImki
KSxOdD17Qk9EWToiYmxvY2sifSxFdD17cG9zaXRpb246ImFic29sdXRlIix2aXNpYmlsaXR5OiJo
aWRkZW4iLGRpc3BsYXk6ImJsb2NrIn0sU3Q9e2xldHRlclNwYWNpbmc6MCxmb250V2VpZ2h0OjQw
MH0sanQ9WyJUb3AiLCJSaWdodCIsIkJvdHRvbSIsIkxlZnQiXSxEdD1bIldlYmtpdCIsIk8iLCJN
b3oiLCJtcyJdO2Z1bmN0aW9uIEF0KGUsdCl7aWYodCBpbiBlKXJldHVybiB0O3ZhciBuPXQuY2hh
ckF0KDApLnRvVXBwZXJDYXNlKCkrdC5zbGljZSgxKSxyPXQsaT1EdC5sZW5ndGg7d2hpbGUoaS0t
KWlmKHQ9RHRbaV0rbix0IGluIGUpcmV0dXJuIHQ7cmV0dXJuIHJ9ZnVuY3Rpb24gTHQoZSx0KXty
ZXR1cm4gZT10fHxlLCJub25lIj09PXguY3NzKGUsImRpc3BsYXkiKXx8IXguY29udGFpbnMoZS5v
d25lckRvY3VtZW50LGUpfWZ1bmN0aW9uIEh0KHQpe3JldHVybiBlLmdldENvbXB1dGVkU3R5bGUo
dCxudWxsKX1mdW5jdGlvbiBxdChlLHQpe3ZhciBuLHIsaSxvPVtdLHM9MCxhPWUubGVuZ3RoO2Zv
cig7YT5zO3MrKylyPWVbc10sci5zdHlsZSYmKG9bc109SC5nZXQociwib2xkZGlzcGxheSIpLG49
ci5zdHlsZS5kaXNwbGF5LHQ/KG9bc118fCJub25lIiE9PW58fChyLnN0eWxlLmRpc3BsYXk9IiIp
LCIiPT09ci5zdHlsZS5kaXNwbGF5JiZMdChyKSYmKG9bc109SC5hY2Nlc3Mociwib2xkZGlzcGxh
eSIsUnQoci5ub2RlTmFtZSkpKSk6b1tzXXx8KGk9THQociksKG4mJiJub25lIiE9PW58fCFpKSYm
SC5zZXQociwib2xkZGlzcGxheSIsaT9uOnguY3NzKHIsImRpc3BsYXkiKSkpKTtmb3Iocz0wO2E+
cztzKyspcj1lW3NdLHIuc3R5bGUmJih0JiYibm9uZSIhPT1yLnN0eWxlLmRpc3BsYXkmJiIiIT09
ci5zdHlsZS5kaXNwbGF5fHwoci5zdHlsZS5kaXNwbGF5PXQ/b1tzXXx8IiI6Im5vbmUiKSk7cmV0
dXJuIGV9eC5mbi5leHRlbmQoe2NzczpmdW5jdGlvbihlLHQpe3JldHVybiB4LmFjY2Vzcyh0aGlz
LGZ1bmN0aW9uKGUsdCxuKXt2YXIgcixpLG89e30scz0wO2lmKHguaXNBcnJheSh0KSl7Zm9yKHI9
SHQoZSksaT10Lmxlbmd0aDtpPnM7cysrKW9bdFtzXV09eC5jc3MoZSx0W3NdLCExLHIpO3JldHVy
biBvfXJldHVybiBuIT09dW5kZWZpbmVkP3guc3R5bGUoZSx0LG4pOnguY3NzKGUsdCl9LGUsdCxh
cmd1bWVudHMubGVuZ3RoPjEpfSxzaG93OmZ1bmN0aW9uKCl7cmV0dXJuIHF0KHRoaXMsITApfSxo
aWRlOmZ1bmN0aW9uKCl7cmV0dXJuIHF0KHRoaXMpfSx0b2dnbGU6ZnVuY3Rpb24oZSl7dmFyIHQ9
ImJvb2xlYW4iPT10eXBlb2YgZTtyZXR1cm4gdGhpcy5lYWNoKGZ1bmN0aW9uKCl7KHQ/ZTpMdCh0
aGlzKSk/eCh0aGlzKS5zaG93KCk6eCh0aGlzKS5oaWRlKCl9KX19KSx4LmV4dGVuZCh7Y3NzSG9v
a3M6e29wYWNpdHk6e2dldDpmdW5jdGlvbihlLHQpe2lmKHQpe3ZhciBuPXZ0KGUsIm9wYWNpdHki
KTtyZXR1cm4iIj09PW4/IjEiOm59fX19LGNzc051bWJlcjp7Y29sdW1uQ291bnQ6ITAsZmlsbE9w
YWNpdHk6ITAsZm9udFdlaWdodDohMCxsaW5lSGVpZ2h0OiEwLG9wYWNpdHk6ITAsb3JwaGFuczoh
MCx3aWRvd3M6ITAsekluZGV4OiEwLHpvb206ITB9LGNzc1Byb3BzOnsiZmxvYXQiOiJjc3NGbG9h
dCJ9LHN0eWxlOmZ1bmN0aW9uKGUsdCxuLHIpe2lmKGUmJjMhPT1lLm5vZGVUeXBlJiY4IT09ZS5u
b2RlVHlwZSYmZS5zdHlsZSl7dmFyIGksbyxzLGE9eC5jYW1lbENhc2UodCksdT1lLnN0eWxlO3Jl
dHVybiB0PXguY3NzUHJvcHNbYV18fCh4LmNzc1Byb3BzW2FdPUF0KHUsYSkpLHM9eC5jc3NIb29r
c1t0XXx8eC5jc3NIb29rc1thXSxuPT09dW5kZWZpbmVkP3MmJiJnZXQiaW4gcyYmKGk9cy5nZXQo
ZSwhMSxyKSkhPT11bmRlZmluZWQ/aTp1W3RdOihvPXR5cGVvZiBuLCJzdHJpbmciPT09byYmKGk9
a3QuZXhlYyhuKSkmJihuPShpWzFdKzEpKmlbMl0rcGFyc2VGbG9hdCh4LmNzcyhlLHQpKSxvPSJu
dW1iZXIiKSxudWxsPT1ufHwibnVtYmVyIj09PW8mJmlzTmFOKG4pfHwoIm51bWJlciIhPT1vfHx4
LmNzc051bWJlclthXXx8KG4rPSJweCIpLHguc3VwcG9ydC5jbGVhckNsb25lU3R5bGV8fCIiIT09
bnx8MCE9PXQuaW5kZXhPZigiYmFja2dyb3VuZCIpfHwodVt0XT0iaW5oZXJpdCIpLHMmJiJzZXQi
aW4gcyYmKG49cy5zZXQoZSxuLHIpKT09PXVuZGVmaW5lZHx8KHVbdF09bikpLHVuZGVmaW5lZCl9
fSxjc3M6ZnVuY3Rpb24oZSx0LG4scil7dmFyIGksbyxzLGE9eC5jYW1lbENhc2UodCk7cmV0dXJu
IHQ9eC5jc3NQcm9wc1thXXx8KHguY3NzUHJvcHNbYV09QXQoZS5zdHlsZSxhKSkscz14LmNzc0hv
b2tzW3RdfHx4LmNzc0hvb2tzW2FdLHMmJiJnZXQiaW4gcyYmKGk9cy5nZXQoZSwhMCxuKSksaT09
PXVuZGVmaW5lZCYmKGk9dnQoZSx0LHIpKSwibm9ybWFsIj09PWkmJnQgaW4gU3QmJihpPVN0W3Rd
KSwiIj09PW58fG4/KG89cGFyc2VGbG9hdChpKSxuPT09ITB8fHguaXNOdW1lcmljKG8pP298fDA6
aSk6aX19KSx2dD1mdW5jdGlvbihlLHQsbil7dmFyIHIsaSxvLHM9bnx8SHQoZSksYT1zP3MuZ2V0
UHJvcGVydHlWYWx1ZSh0KXx8c1t0XTp1bmRlZmluZWQsdT1lLnN0eWxlO3JldHVybiBzJiYoIiIh
PT1hfHx4LmNvbnRhaW5zKGUub3duZXJEb2N1bWVudCxlKXx8KGE9eC5zdHlsZShlLHQpKSxDdC50
ZXN0KGEpJiZ3dC50ZXN0KHQpJiYocj11LndpZHRoLGk9dS5taW5XaWR0aCxvPXUubWF4V2lkdGgs
dS5taW5XaWR0aD11Lm1heFdpZHRoPXUud2lkdGg9YSxhPXMud2lkdGgsdS53aWR0aD1yLHUubWlu
V2lkdGg9aSx1Lm1heFdpZHRoPW8pKSxhfTtmdW5jdGlvbiBPdChlLHQsbil7dmFyIHI9VHQuZXhl
Yyh0KTtyZXR1cm4gcj9NYXRoLm1heCgwLHJbMV0tKG58fDApKSsoclsyXXx8InB4Iik6dH1mdW5j
dGlvbiBGdChlLHQsbixyLGkpe3ZhciBvPW49PT0ocj8iYm9yZGVyIjoiY29udGVudCIpPzQ6Indp
ZHRoIj09PXQ/MTowLHM9MDtmb3IoOzQ+bztvKz0yKSJtYXJnaW4iPT09biYmKHMrPXguY3NzKGUs
bitqdFtvXSwhMCxpKSkscj8oImNvbnRlbnQiPT09biYmKHMtPXguY3NzKGUsInBhZGRpbmciK2p0
W29dLCEwLGkpKSwibWFyZ2luIiE9PW4mJihzLT14LmNzcyhlLCJib3JkZXIiK2p0W29dKyJXaWR0
aCIsITAsaSkpKToocys9eC5jc3MoZSwicGFkZGluZyIranRbb10sITAsaSksInBhZGRpbmciIT09
biYmKHMrPXguY3NzKGUsImJvcmRlciIranRbb10rIldpZHRoIiwhMCxpKSkpO3JldHVybiBzfWZ1
bmN0aW9uIFB0KGUsdCxuKXt2YXIgcj0hMCxpPSJ3aWR0aCI9PT10P2Uub2Zmc2V0V2lkdGg6ZS5v
ZmZzZXRIZWlnaHQsbz1IdChlKSxzPXguc3VwcG9ydC5ib3hTaXppbmcmJiJib3JkZXItYm94Ij09
PXguY3NzKGUsImJveFNpemluZyIsITEsbyk7aWYoMD49aXx8bnVsbD09aSl7aWYoaT12dChlLHQs
byksKDA+aXx8bnVsbD09aSkmJihpPWUuc3R5bGVbdF0pLEN0LnRlc3QoaSkpcmV0dXJuIGk7cj1z
JiYoeC5zdXBwb3J0LmJveFNpemluZ1JlbGlhYmxlfHxpPT09ZS5zdHlsZVt0XSksaT1wYXJzZUZs
b2F0KGkpfHwwfXJldHVybiBpK0Z0KGUsdCxufHwocz8iYm9yZGVyIjoiY29udGVudCIpLHIsbykr
InB4In1mdW5jdGlvbiBSdChlKXt2YXIgdD1vLG49TnRbZV07cmV0dXJuIG58fChuPU10KGUsdCks
Im5vbmUiIT09biYmbnx8KHh0PSh4dHx8eCgiPGlmcmFtZSBmcmFtZWJvcmRlcj0nMCcgd2lkdGg9
JzAnIGhlaWdodD0nMCcvPiIpLmNzcygiY3NzVGV4dCIsImRpc3BsYXk6YmxvY2sgIWltcG9ydGFu
dCIpKS5hcHBlbmRUbyh0LmRvY3VtZW50RWxlbWVudCksdD0oeHRbMF0uY29udGVudFdpbmRvd3x8
eHRbMF0uY29udGVudERvY3VtZW50KS5kb2N1bWVudCx0LndyaXRlKCI8IWRvY3R5cGUgaHRtbD48
aHRtbD48Ym9keT4iKSx0LmNsb3NlKCksbj1NdChlLHQpLHh0LmRldGFjaCgpKSxOdFtlXT1uKSxu
fWZ1bmN0aW9uIE10KGUsdCl7dmFyIG49eCh0LmNyZWF0ZUVsZW1lbnQoZSkpLmFwcGVuZFRvKHQu
Ym9keSkscj14LmNzcyhuWzBdLCJkaXNwbGF5Iik7cmV0dXJuIG4ucmVtb3ZlKCkscn14LmVhY2go
WyJoZWlnaHQiLCJ3aWR0aCJdLGZ1bmN0aW9uKGUsdCl7eC5jc3NIb29rc1t0XT17Z2V0OmZ1bmN0
aW9uKGUsbixyKXtyZXR1cm4gbj8wPT09ZS5vZmZzZXRXaWR0aCYmYnQudGVzdCh4LmNzcyhlLCJk
aXNwbGF5IikpP3guc3dhcChlLEV0LGZ1bmN0aW9uKCl7cmV0dXJuIFB0KGUsdCxyKX0pOlB0KGUs
dCxyKTp1bmRlZmluZWR9LHNldDpmdW5jdGlvbihlLG4scil7dmFyIGk9ciYmSHQoZSk7cmV0dXJu
IE90KGUsbixyP0Z0KGUsdCxyLHguc3VwcG9ydC5ib3hTaXppbmcmJiJib3JkZXItYm94Ij09PXgu
Y3NzKGUsImJveFNpemluZyIsITEsaSksaSk6MCl9fX0pLHgoZnVuY3Rpb24oKXt4LnN1cHBvcnQu
cmVsaWFibGVNYXJnaW5SaWdodHx8KHguY3NzSG9va3MubWFyZ2luUmlnaHQ9e2dldDpmdW5jdGlv
bihlLHQpe3JldHVybiB0P3guc3dhcChlLHtkaXNwbGF5OiJpbmxpbmUtYmxvY2sifSx2dCxbZSwi
bWFyZ2luUmlnaHQiXSk6dW5kZWZpbmVkfX0pLCF4LnN1cHBvcnQucGl4ZWxQb3NpdGlvbiYmeC5m
bi5wb3NpdGlvbiYmeC5lYWNoKFsidG9wIiwibGVmdCJdLGZ1bmN0aW9uKGUsdCl7eC5jc3NIb29r
c1t0XT17Z2V0OmZ1bmN0aW9uKGUsbil7cmV0dXJuIG4/KG49dnQoZSx0KSxDdC50ZXN0KG4pP3go
ZSkucG9zaXRpb24oKVt0XSsicHgiOm4pOnVuZGVmaW5lZH19fSl9KSx4LmV4cHImJnguZXhwci5m
aWx0ZXJzJiYoeC5leHByLmZpbHRlcnMuaGlkZGVuPWZ1bmN0aW9uKGUpe3JldHVybiAwPj1lLm9m
ZnNldFdpZHRoJiYwPj1lLm9mZnNldEhlaWdodH0seC5leHByLmZpbHRlcnMudmlzaWJsZT1mdW5j
dGlvbihlKXtyZXR1cm4heC5leHByLmZpbHRlcnMuaGlkZGVuKGUpfSkseC5lYWNoKHttYXJnaW46
IiIscGFkZGluZzoiIixib3JkZXI6IldpZHRoIn0sZnVuY3Rpb24oZSx0KXt4LmNzc0hvb2tzW2Ur
dF09e2V4cGFuZDpmdW5jdGlvbihuKXt2YXIgcj0wLGk9e30sbz0ic3RyaW5nIj09dHlwZW9mIG4/
bi5zcGxpdCgiICIpOltuXTtmb3IoOzQ+cjtyKyspaVtlK2p0W3JdK3RdPW9bcl18fG9bci0yXXx8
b1swXTtyZXR1cm4gaX19LHd0LnRlc3QoZSl8fCh4LmNzc0hvb2tzW2UrdF0uc2V0PU90KX0pO3Zh
ciBXdD0vJTIwL2csJHQ9L1xbXF0kLyxCdD0vXHI/XG4vZyxJdD0vXig/OnN1Ym1pdHxidXR0b258
aW1hZ2V8cmVzZXR8ZmlsZSkkL2ksenQ9L14oPzppbnB1dHxzZWxlY3R8dGV4dGFyZWF8a2V5Z2Vu
KS9pO3guZm4uZXh0ZW5kKHtzZXJpYWxpemU6ZnVuY3Rpb24oKXtyZXR1cm4geC5wYXJhbSh0aGlz
LnNlcmlhbGl6ZUFycmF5KCkpfSxzZXJpYWxpemVBcnJheTpmdW5jdGlvbigpe3JldHVybiB0aGlz
Lm1hcChmdW5jdGlvbigpe3ZhciBlPXgucHJvcCh0aGlzLCJlbGVtZW50cyIpO3JldHVybiBlP3gu
bWFrZUFycmF5KGUpOnRoaXN9KS5maWx0ZXIoZnVuY3Rpb24oKXt2YXIgZT10aGlzLnR5cGU7cmV0
dXJuIHRoaXMubmFtZSYmIXgodGhpcykuaXMoIjpkaXNhYmxlZCIpJiZ6dC50ZXN0KHRoaXMubm9k
ZU5hbWUpJiYhSXQudGVzdChlKSYmKHRoaXMuY2hlY2tlZHx8IW90LnRlc3QoZSkpfSkubWFwKGZ1
bmN0aW9uKGUsdCl7dmFyIG49eCh0aGlzKS52YWwoKTtyZXR1cm4gbnVsbD09bj9udWxsOnguaXNB
cnJheShuKT94Lm1hcChuLGZ1bmN0aW9uKGUpe3JldHVybntuYW1lOnQubmFtZSx2YWx1ZTplLnJl
cGxhY2UoQnQsIlxyXG4iKX19KTp7bmFtZTp0Lm5hbWUsdmFsdWU6bi5yZXBsYWNlKEJ0LCJcclxu
Iil9fSkuZ2V0KCl9fSkseC5wYXJhbT1mdW5jdGlvbihlLHQpe3ZhciBuLHI9W10saT1mdW5jdGlv
bihlLHQpe3Q9eC5pc0Z1bmN0aW9uKHQpP3QoKTpudWxsPT10PyIiOnQscltyLmxlbmd0aF09ZW5j
b2RlVVJJQ29tcG9uZW50KGUpKyI9IitlbmNvZGVVUklDb21wb25lbnQodCl9O2lmKHQ9PT11bmRl
ZmluZWQmJih0PXguYWpheFNldHRpbmdzJiZ4LmFqYXhTZXR0aW5ncy50cmFkaXRpb25hbCkseC5p
c0FycmF5KGUpfHxlLmpxdWVyeSYmIXguaXNQbGFpbk9iamVjdChlKSl4LmVhY2goZSxmdW5jdGlv
bigpe2kodGhpcy5uYW1lLHRoaXMudmFsdWUpfSk7ZWxzZSBmb3IobiBpbiBlKV90KG4sZVtuXSx0
LGkpO3JldHVybiByLmpvaW4oIiYiKS5yZXBsYWNlKFd0LCIrIil9O2Z1bmN0aW9uIF90KGUsdCxu
LHIpe3ZhciBpO2lmKHguaXNBcnJheSh0KSl4LmVhY2godCxmdW5jdGlvbih0LGkpe258fCR0LnRl
c3QoZSk/cihlLGkpOl90KGUrIlsiKygib2JqZWN0Ij09dHlwZW9mIGk/dDoiIikrIl0iLGksbixy
KX0pO2Vsc2UgaWYobnx8Im9iamVjdCIhPT14LnR5cGUodCkpcihlLHQpO2Vsc2UgZm9yKGkgaW4g
dClfdChlKyJbIitpKyJdIix0W2ldLG4scil9eC5lYWNoKCJibHVyIGZvY3VzIGZvY3VzaW4gZm9j
dXNvdXQgbG9hZCByZXNpemUgc2Nyb2xsIHVubG9hZCBjbGljayBkYmxjbGljayBtb3VzZWRvd24g
bW91c2V1cCBtb3VzZW1vdmUgbW91c2VvdmVyIG1vdXNlb3V0IG1vdXNlZW50ZXIgbW91c2VsZWF2
ZSBjaGFuZ2Ugc2VsZWN0IHN1Ym1pdCBrZXlkb3duIGtleXByZXNzIGtleXVwIGVycm9yIGNvbnRl
eHRtZW51Ii5zcGxpdCgiICIpLGZ1bmN0aW9uKGUsdCl7eC5mblt0XT1mdW5jdGlvbihlLG4pe3Jl
dHVybiBhcmd1bWVudHMubGVuZ3RoPjA/dGhpcy5vbih0LG51bGwsZSxuKTp0aGlzLnRyaWdnZXIo
dCl9fSkseC5mbi5leHRlbmQoe2hvdmVyOmZ1bmN0aW9uKGUsdCl7cmV0dXJuIHRoaXMubW91c2Vl
bnRlcihlKS5tb3VzZWxlYXZlKHR8fGUpfSxiaW5kOmZ1bmN0aW9uKGUsdCxuKXtyZXR1cm4gdGhp
cy5vbihlLG51bGwsdCxuKX0sdW5iaW5kOmZ1bmN0aW9uKGUsdCl7cmV0dXJuIHRoaXMub2ZmKGUs
bnVsbCx0KX0sZGVsZWdhdGU6ZnVuY3Rpb24oZSx0LG4scil7cmV0dXJuIHRoaXMub24odCxlLG4s
cil9LHVuZGVsZWdhdGU6ZnVuY3Rpb24oZSx0LG4pe3JldHVybiAxPT09YXJndW1lbnRzLmxlbmd0
aD90aGlzLm9mZihlLCIqKiIpOnRoaXMub2ZmKHQsZXx8IioqIixuKQp9fSk7dmFyIFh0LFV0LFl0
PXgubm93KCksVnQ9L1w/LyxHdD0vIy4qJC8sSnQ9LyhbPyZdKV89W14mXSovLFF0PS9eKC4qPyk6
WyBcdF0qKFteXHJcbl0qKSQvZ20sS3Q9L14oPzphYm91dHxhcHB8YXBwLXN0b3JhZ2V8ListZXh0
ZW5zaW9ufGZpbGV8cmVzfHdpZGdldCk6JC8sWnQ9L14oPzpHRVR8SEVBRCkkLyxlbj0vXlwvXC8v
LHRuPS9eKFtcdy4rLV0rOikoPzpcL1wvKFteXC8/IzpdKikoPzo6KFxkKyl8KXwpLyxubj14LmZu
LmxvYWQscm49e30sb249e30sc249IiovIi5jb25jYXQoIioiKTt0cnl7VXQ9aS5ocmVmfWNhdGNo
KGFuKXtVdD1vLmNyZWF0ZUVsZW1lbnQoImEiKSxVdC5ocmVmPSIiLFV0PVV0LmhyZWZ9WHQ9dG4u
ZXhlYyhVdC50b0xvd2VyQ2FzZSgpKXx8W107ZnVuY3Rpb24gdW4oZSl7cmV0dXJuIGZ1bmN0aW9u
KHQsbil7InN0cmluZyIhPXR5cGVvZiB0JiYobj10LHQ9IioiKTt2YXIgcixpPTAsbz10LnRvTG93
ZXJDYXNlKCkubWF0Y2godyl8fFtdO2lmKHguaXNGdW5jdGlvbihuKSl3aGlsZShyPW9baSsrXSki
KyI9PT1yWzBdPyhyPXIuc2xpY2UoMSl8fCIqIiwoZVtyXT1lW3JdfHxbXSkudW5zaGlmdChuKSk6
KGVbcl09ZVtyXXx8W10pLnB1c2gobil9fWZ1bmN0aW9uIGxuKGUsdCxuLHIpe3ZhciBpPXt9LG89
ZT09PW9uO2Z1bmN0aW9uIHMoYSl7dmFyIHU7cmV0dXJuIGlbYV09ITAseC5lYWNoKGVbYV18fFtd
LGZ1bmN0aW9uKGUsYSl7dmFyIGw9YSh0LG4scik7cmV0dXJuInN0cmluZyIhPXR5cGVvZiBsfHxv
fHxpW2xdP28/ISh1PWwpOnVuZGVmaW5lZDoodC5kYXRhVHlwZXMudW5zaGlmdChsKSxzKGwpLCEx
KX0pLHV9cmV0dXJuIHModC5kYXRhVHlwZXNbMF0pfHwhaVsiKiJdJiZzKCIqIil9ZnVuY3Rpb24g
Y24oZSx0KXt2YXIgbixyLGk9eC5hamF4U2V0dGluZ3MuZmxhdE9wdGlvbnN8fHt9O2ZvcihuIGlu
IHQpdFtuXSE9PXVuZGVmaW5lZCYmKChpW25dP2U6cnx8KHI9e30pKVtuXT10W25dKTtyZXR1cm4g
ciYmeC5leHRlbmQoITAsZSxyKSxlfXguZm4ubG9hZD1mdW5jdGlvbihlLHQsbil7aWYoInN0cmlu
ZyIhPXR5cGVvZiBlJiZubilyZXR1cm4gbm4uYXBwbHkodGhpcyxhcmd1bWVudHMpO3ZhciByLGks
byxzPXRoaXMsYT1lLmluZGV4T2YoIiAiKTtyZXR1cm4gYT49MCYmKHI9ZS5zbGljZShhKSxlPWUu
c2xpY2UoMCxhKSkseC5pc0Z1bmN0aW9uKHQpPyhuPXQsdD11bmRlZmluZWQpOnQmJiJvYmplY3Qi
PT10eXBlb2YgdCYmKGk9IlBPU1QiKSxzLmxlbmd0aD4wJiZ4LmFqYXgoe3VybDplLHR5cGU6aSxk
YXRhVHlwZToiaHRtbCIsZGF0YTp0fSkuZG9uZShmdW5jdGlvbihlKXtvPWFyZ3VtZW50cyxzLmh0
bWwocj94KCI8ZGl2PiIpLmFwcGVuZCh4LnBhcnNlSFRNTChlKSkuZmluZChyKTplKX0pLmNvbXBs
ZXRlKG4mJmZ1bmN0aW9uKGUsdCl7cy5lYWNoKG4sb3x8W2UucmVzcG9uc2VUZXh0LHQsZV0pfSks
dGhpc30seC5lYWNoKFsiYWpheFN0YXJ0IiwiYWpheFN0b3AiLCJhamF4Q29tcGxldGUiLCJhamF4
RXJyb3IiLCJhamF4U3VjY2VzcyIsImFqYXhTZW5kIl0sZnVuY3Rpb24oZSx0KXt4LmZuW3RdPWZ1
bmN0aW9uKGUpe3JldHVybiB0aGlzLm9uKHQsZSl9fSkseC5leHRlbmQoe2FjdGl2ZTowLGxhc3RN
b2RpZmllZDp7fSxldGFnOnt9LGFqYXhTZXR0aW5nczp7dXJsOlV0LHR5cGU6IkdFVCIsaXNMb2Nh
bDpLdC50ZXN0KFh0WzFdKSxnbG9iYWw6ITAscHJvY2Vzc0RhdGE6ITAsYXN5bmM6ITAsY29udGVu
dFR5cGU6ImFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZDsgY2hhcnNldD1VVEYtOCIs
YWNjZXB0czp7IioiOnNuLHRleHQ6InRleHQvcGxhaW4iLGh0bWw6InRleHQvaHRtbCIseG1sOiJh
cHBsaWNhdGlvbi94bWwsIHRleHQveG1sIixqc29uOiJhcHBsaWNhdGlvbi9qc29uLCB0ZXh0L2ph
dmFzY3JpcHQifSxjb250ZW50czp7eG1sOi94bWwvLGh0bWw6L2h0bWwvLGpzb246L2pzb24vfSxy
ZXNwb25zZUZpZWxkczp7eG1sOiJyZXNwb25zZVhNTCIsdGV4dDoicmVzcG9uc2VUZXh0Iixqc29u
OiJyZXNwb25zZUpTT04ifSxjb252ZXJ0ZXJzOnsiKiB0ZXh0IjpTdHJpbmcsInRleHQgaHRtbCI6
ITAsInRleHQganNvbiI6eC5wYXJzZUpTT04sInRleHQgeG1sIjp4LnBhcnNlWE1MfSxmbGF0T3B0
aW9uczp7dXJsOiEwLGNvbnRleHQ6ITB9fSxhamF4U2V0dXA6ZnVuY3Rpb24oZSx0KXtyZXR1cm4g
dD9jbihjbihlLHguYWpheFNldHRpbmdzKSx0KTpjbih4LmFqYXhTZXR0aW5ncyxlKX0sYWpheFBy
ZWZpbHRlcjp1bihybiksYWpheFRyYW5zcG9ydDp1bihvbiksYWpheDpmdW5jdGlvbihlLHQpeyJv
YmplY3QiPT10eXBlb2YgZSYmKHQ9ZSxlPXVuZGVmaW5lZCksdD10fHx7fTt2YXIgbixyLGksbyxz
LGEsdSxsLGM9eC5hamF4U2V0dXAoe30sdCksZj1jLmNvbnRleHR8fGMscD1jLmNvbnRleHQmJihm
Lm5vZGVUeXBlfHxmLmpxdWVyeSk/eChmKTp4LmV2ZW50LGg9eC5EZWZlcnJlZCgpLGQ9eC5DYWxs
YmFja3MoIm9uY2UgbWVtb3J5IiksZz1jLnN0YXR1c0NvZGV8fHt9LG09e30seT17fSx2PTAsYj0i
Y2FuY2VsZWQiLFQ9e3JlYWR5U3RhdGU6MCxnZXRSZXNwb25zZUhlYWRlcjpmdW5jdGlvbihlKXt2
YXIgdDtpZigyPT09dil7aWYoIW8pe289e307d2hpbGUodD1RdC5leGVjKGkpKW9bdFsxXS50b0xv
d2VyQ2FzZSgpXT10WzJdfXQ9b1tlLnRvTG93ZXJDYXNlKCldfXJldHVybiBudWxsPT10P251bGw6
dH0sZ2V0QWxsUmVzcG9uc2VIZWFkZXJzOmZ1bmN0aW9uKCl7cmV0dXJuIDI9PT12P2k6bnVsbH0s
c2V0UmVxdWVzdEhlYWRlcjpmdW5jdGlvbihlLHQpe3ZhciBuPWUudG9Mb3dlckNhc2UoKTtyZXR1
cm4gdnx8KGU9eVtuXT15W25dfHxlLG1bZV09dCksdGhpc30sb3ZlcnJpZGVNaW1lVHlwZTpmdW5j
dGlvbihlKXtyZXR1cm4gdnx8KGMubWltZVR5cGU9ZSksdGhpc30sc3RhdHVzQ29kZTpmdW5jdGlv
bihlKXt2YXIgdDtpZihlKWlmKDI+dilmb3IodCBpbiBlKWdbdF09W2dbdF0sZVt0XV07ZWxzZSBU
LmFsd2F5cyhlW1Quc3RhdHVzXSk7cmV0dXJuIHRoaXN9LGFib3J0OmZ1bmN0aW9uKGUpe3ZhciB0
PWV8fGI7cmV0dXJuIG4mJm4uYWJvcnQodCksaygwLHQpLHRoaXN9fTtpZihoLnByb21pc2UoVCku
Y29tcGxldGU9ZC5hZGQsVC5zdWNjZXNzPVQuZG9uZSxULmVycm9yPVQuZmFpbCxjLnVybD0oKGV8
fGMudXJsfHxVdCkrIiIpLnJlcGxhY2UoR3QsIiIpLnJlcGxhY2UoZW4sWHRbMV0rIi8vIiksYy50
eXBlPXQubWV0aG9kfHx0LnR5cGV8fGMubWV0aG9kfHxjLnR5cGUsYy5kYXRhVHlwZXM9eC50cmlt
KGMuZGF0YVR5cGV8fCIqIikudG9Mb3dlckNhc2UoKS5tYXRjaCh3KXx8WyIiXSxudWxsPT1jLmNy
b3NzRG9tYWluJiYoYT10bi5leGVjKGMudXJsLnRvTG93ZXJDYXNlKCkpLGMuY3Jvc3NEb21haW49
ISghYXx8YVsxXT09PVh0WzFdJiZhWzJdPT09WHRbMl0mJihhWzNdfHwoImh0dHA6Ij09PWFbMV0/
IjgwIjoiNDQzIikpPT09KFh0WzNdfHwoImh0dHA6Ij09PVh0WzFdPyI4MCI6IjQ0MyIpKSkpLGMu
ZGF0YSYmYy5wcm9jZXNzRGF0YSYmInN0cmluZyIhPXR5cGVvZiBjLmRhdGEmJihjLmRhdGE9eC5w
YXJhbShjLmRhdGEsYy50cmFkaXRpb25hbCkpLGxuKHJuLGMsdCxUKSwyPT09dilyZXR1cm4gVDt1
PWMuZ2xvYmFsLHUmJjA9PT14LmFjdGl2ZSsrJiZ4LmV2ZW50LnRyaWdnZXIoImFqYXhTdGFydCIp
LGMudHlwZT1jLnR5cGUudG9VcHBlckNhc2UoKSxjLmhhc0NvbnRlbnQ9IVp0LnRlc3QoYy50eXBl
KSxyPWMudXJsLGMuaGFzQ29udGVudHx8KGMuZGF0YSYmKHI9Yy51cmwrPShWdC50ZXN0KHIpPyIm
IjoiPyIpK2MuZGF0YSxkZWxldGUgYy5kYXRhKSxjLmNhY2hlPT09ITEmJihjLnVybD1KdC50ZXN0
KHIpP3IucmVwbGFjZShKdCwiJDFfPSIrWXQrKyk6cisoVnQudGVzdChyKT8iJiI6Ij8iKSsiXz0i
K1l0KyspKSxjLmlmTW9kaWZpZWQmJih4Lmxhc3RNb2RpZmllZFtyXSYmVC5zZXRSZXF1ZXN0SGVh
ZGVyKCJJZi1Nb2RpZmllZC1TaW5jZSIseC5sYXN0TW9kaWZpZWRbcl0pLHguZXRhZ1tyXSYmVC5z
ZXRSZXF1ZXN0SGVhZGVyKCJJZi1Ob25lLU1hdGNoIix4LmV0YWdbcl0pKSwoYy5kYXRhJiZjLmhh
c0NvbnRlbnQmJmMuY29udGVudFR5cGUhPT0hMXx8dC5jb250ZW50VHlwZSkmJlQuc2V0UmVxdWVz
dEhlYWRlcigiQ29udGVudC1UeXBlIixjLmNvbnRlbnRUeXBlKSxULnNldFJlcXVlc3RIZWFkZXIo
IkFjY2VwdCIsYy5kYXRhVHlwZXNbMF0mJmMuYWNjZXB0c1tjLmRhdGFUeXBlc1swXV0/Yy5hY2Nl
cHRzW2MuZGF0YVR5cGVzWzBdXSsoIioiIT09Yy5kYXRhVHlwZXNbMF0/IiwgIitzbisiOyBxPTAu
MDEiOiIiKTpjLmFjY2VwdHNbIioiXSk7Zm9yKGwgaW4gYy5oZWFkZXJzKVQuc2V0UmVxdWVzdEhl
YWRlcihsLGMuaGVhZGVyc1tsXSk7aWYoYy5iZWZvcmVTZW5kJiYoYy5iZWZvcmVTZW5kLmNhbGwo
ZixULGMpPT09ITF8fDI9PT12KSlyZXR1cm4gVC5hYm9ydCgpO2I9ImFib3J0Ijtmb3IobCBpbntz
dWNjZXNzOjEsZXJyb3I6MSxjb21wbGV0ZToxfSlUW2xdKGNbbF0pO2lmKG49bG4ob24sYyx0LFQp
KXtULnJlYWR5U3RhdGU9MSx1JiZwLnRyaWdnZXIoImFqYXhTZW5kIixbVCxjXSksYy5hc3luYyYm
Yy50aW1lb3V0PjAmJihzPXNldFRpbWVvdXQoZnVuY3Rpb24oKXtULmFib3J0KCJ0aW1lb3V0Iil9
LGMudGltZW91dCkpO3RyeXt2PTEsbi5zZW5kKG0sayl9Y2F0Y2goQyl7aWYoISgyPnYpKXRocm93
IEM7aygtMSxDKX19ZWxzZSBrKC0xLCJObyBUcmFuc3BvcnQiKTtmdW5jdGlvbiBrKGUsdCxvLGEp
e3ZhciBsLG0seSxiLHcsQz10OzIhPT12JiYodj0yLHMmJmNsZWFyVGltZW91dChzKSxuPXVuZGVm
aW5lZCxpPWF8fCIiLFQucmVhZHlTdGF0ZT1lPjA/NDowLGw9ZT49MjAwJiYzMDA+ZXx8MzA0PT09
ZSxvJiYoYj1mbihjLFQsbykpLGI9cG4oYyxiLFQsbCksbD8oYy5pZk1vZGlmaWVkJiYodz1ULmdl
dFJlc3BvbnNlSGVhZGVyKCJMYXN0LU1vZGlmaWVkIiksdyYmKHgubGFzdE1vZGlmaWVkW3JdPXcp
LHc9VC5nZXRSZXNwb25zZUhlYWRlcigiZXRhZyIpLHcmJih4LmV0YWdbcl09dykpLDIwND09PWV8
fCJIRUFEIj09PWMudHlwZT9DPSJub2NvbnRlbnQiOjMwND09PWU/Qz0ibm90bW9kaWZpZWQiOihD
PWIuc3RhdGUsbT1iLmRhdGEseT1iLmVycm9yLGw9IXkpKTooeT1DLChlfHwhQykmJihDPSJlcnJv
ciIsMD5lJiYoZT0wKSkpLFQuc3RhdHVzPWUsVC5zdGF0dXNUZXh0PSh0fHxDKSsiIixsP2gucmVz
b2x2ZVdpdGgoZixbbSxDLFRdKTpoLnJlamVjdFdpdGgoZixbVCxDLHldKSxULnN0YXR1c0NvZGUo
ZyksZz11bmRlZmluZWQsdSYmcC50cmlnZ2VyKGw/ImFqYXhTdWNjZXNzIjoiYWpheEVycm9yIixb
VCxjLGw/bTp5XSksZC5maXJlV2l0aChmLFtULENdKSx1JiYocC50cmlnZ2VyKCJhamF4Q29tcGxl
dGUiLFtULGNdKSwtLXguYWN0aXZlfHx4LmV2ZW50LnRyaWdnZXIoImFqYXhTdG9wIikpKX1yZXR1
cm4gVH0sZ2V0SlNPTjpmdW5jdGlvbihlLHQsbil7cmV0dXJuIHguZ2V0KGUsdCxuLCJqc29uIil9
LGdldFNjcmlwdDpmdW5jdGlvbihlLHQpe3JldHVybiB4LmdldChlLHVuZGVmaW5lZCx0LCJzY3Jp
cHQiKX19KSx4LmVhY2goWyJnZXQiLCJwb3N0Il0sZnVuY3Rpb24oZSx0KXt4W3RdPWZ1bmN0aW9u
KGUsbixyLGkpe3JldHVybiB4LmlzRnVuY3Rpb24obikmJihpPWl8fHIscj1uLG49dW5kZWZpbmVk
KSx4LmFqYXgoe3VybDplLHR5cGU6dCxkYXRhVHlwZTppLGRhdGE6bixzdWNjZXNzOnJ9KX19KTtm
dW5jdGlvbiBmbihlLHQsbil7dmFyIHIsaSxvLHMsYT1lLmNvbnRlbnRzLHU9ZS5kYXRhVHlwZXM7
d2hpbGUoIioiPT09dVswXSl1LnNoaWZ0KCkscj09PXVuZGVmaW5lZCYmKHI9ZS5taW1lVHlwZXx8
dC5nZXRSZXNwb25zZUhlYWRlcigiQ29udGVudC1UeXBlIikpO2lmKHIpZm9yKGkgaW4gYSlpZihh
W2ldJiZhW2ldLnRlc3Qocikpe3UudW5zaGlmdChpKTticmVha31pZih1WzBdaW4gbilvPXVbMF07
ZWxzZXtmb3IoaSBpbiBuKXtpZighdVswXXx8ZS5jb252ZXJ0ZXJzW2krIiAiK3VbMF1dKXtvPWk7
YnJlYWt9c3x8KHM9aSl9bz1vfHxzfXJldHVybiBvPyhvIT09dVswXSYmdS51bnNoaWZ0KG8pLG5b
b10pOnVuZGVmaW5lZH1mdW5jdGlvbiBwbihlLHQsbixyKXt2YXIgaSxvLHMsYSx1LGw9e30sYz1l
LmRhdGFUeXBlcy5zbGljZSgpO2lmKGNbMV0pZm9yKHMgaW4gZS5jb252ZXJ0ZXJzKWxbcy50b0xv
d2VyQ2FzZSgpXT1lLmNvbnZlcnRlcnNbc107bz1jLnNoaWZ0KCk7d2hpbGUobylpZihlLnJlc3Bv
bnNlRmllbGRzW29dJiYobltlLnJlc3BvbnNlRmllbGRzW29dXT10KSwhdSYmciYmZS5kYXRhRmls
dGVyJiYodD1lLmRhdGFGaWx0ZXIodCxlLmRhdGFUeXBlKSksdT1vLG89Yy5zaGlmdCgpKWlmKCIq
Ij09PW8pbz11O2Vsc2UgaWYoIioiIT09dSYmdSE9PW8pe2lmKHM9bFt1KyIgIitvXXx8bFsiKiAi
K29dLCFzKWZvcihpIGluIGwpaWYoYT1pLnNwbGl0KCIgIiksYVsxXT09PW8mJihzPWxbdSsiICIr
YVswXV18fGxbIiogIithWzBdXSkpe3M9PT0hMD9zPWxbaV06bFtpXSE9PSEwJiYobz1hWzBdLGMu
dW5zaGlmdChhWzFdKSk7YnJlYWt9aWYocyE9PSEwKWlmKHMmJmVbInRocm93cyJdKXQ9cyh0KTtl
bHNlIHRyeXt0PXModCl9Y2F0Y2goZil7cmV0dXJue3N0YXRlOiJwYXJzZXJlcnJvciIsZXJyb3I6
cz9mOiJObyBjb252ZXJzaW9uIGZyb20gIit1KyIgdG8gIitvfX19cmV0dXJue3N0YXRlOiJzdWNj
ZXNzIixkYXRhOnR9fXguYWpheFNldHVwKHthY2NlcHRzOntzY3JpcHQ6InRleHQvamF2YXNjcmlw
dCwgYXBwbGljYXRpb24vamF2YXNjcmlwdCwgYXBwbGljYXRpb24vZWNtYXNjcmlwdCwgYXBwbGlj
YXRpb24veC1lY21hc2NyaXB0In0sY29udGVudHM6e3NjcmlwdDovKD86amF2YXxlY21hKXNjcmlw
dC99LGNvbnZlcnRlcnM6eyJ0ZXh0IHNjcmlwdCI6ZnVuY3Rpb24oZSl7cmV0dXJuIHguZ2xvYmFs
RXZhbChlKSxlfX19KSx4LmFqYXhQcmVmaWx0ZXIoInNjcmlwdCIsZnVuY3Rpb24oZSl7ZS5jYWNo
ZT09PXVuZGVmaW5lZCYmKGUuY2FjaGU9ITEpLGUuY3Jvc3NEb21haW4mJihlLnR5cGU9IkdFVCIp
fSkseC5hamF4VHJhbnNwb3J0KCJzY3JpcHQiLGZ1bmN0aW9uKGUpe2lmKGUuY3Jvc3NEb21haW4p
e3ZhciB0LG47cmV0dXJue3NlbmQ6ZnVuY3Rpb24ocixpKXt0PXgoIjxzY3JpcHQ+IikucHJvcCh7
YXN5bmM6ITAsY2hhcnNldDplLnNjcmlwdENoYXJzZXQsc3JjOmUudXJsfSkub24oImxvYWQgZXJy
b3IiLG49ZnVuY3Rpb24oZSl7dC5yZW1vdmUoKSxuPW51bGwsZSYmaSgiZXJyb3IiPT09ZS50eXBl
PzQwNDoyMDAsZS50eXBlKX0pLG8uaGVhZC5hcHBlbmRDaGlsZCh0WzBdKX0sYWJvcnQ6ZnVuY3Rp
b24oKXtuJiZuKCl9fX19KTt2YXIgaG49W10sZG49Lyg9KVw/KD89JnwkKXxcP1w/Lzt4LmFqYXhT
ZXR1cCh7anNvbnA6ImNhbGxiYWNrIixqc29ucENhbGxiYWNrOmZ1bmN0aW9uKCl7dmFyIGU9aG4u
cG9wKCl8fHguZXhwYW5kbysiXyIrWXQrKztyZXR1cm4gdGhpc1tlXT0hMCxlfX0pLHguYWpheFBy
ZWZpbHRlcigianNvbiBqc29ucCIsZnVuY3Rpb24odCxuLHIpe3ZhciBpLG8scyxhPXQuanNvbnAh
PT0hMSYmKGRuLnRlc3QodC51cmwpPyJ1cmwiOiJzdHJpbmciPT10eXBlb2YgdC5kYXRhJiYhKHQu
Y29udGVudFR5cGV8fCIiKS5pbmRleE9mKCJhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29k
ZWQiKSYmZG4udGVzdCh0LmRhdGEpJiYiZGF0YSIpO3JldHVybiBhfHwianNvbnAiPT09dC5kYXRh
VHlwZXNbMF0/KGk9dC5qc29ucENhbGxiYWNrPXguaXNGdW5jdGlvbih0Lmpzb25wQ2FsbGJhY2sp
P3QuanNvbnBDYWxsYmFjaygpOnQuanNvbnBDYWxsYmFjayxhP3RbYV09dFthXS5yZXBsYWNlKGRu
LCIkMSIraSk6dC5qc29ucCE9PSExJiYodC51cmwrPShWdC50ZXN0KHQudXJsKT8iJiI6Ij8iKSt0
Lmpzb25wKyI9IitpKSx0LmNvbnZlcnRlcnNbInNjcmlwdCBqc29uIl09ZnVuY3Rpb24oKXtyZXR1
cm4gc3x8eC5lcnJvcihpKyIgd2FzIG5vdCBjYWxsZWQiKSxzWzBdfSx0LmRhdGFUeXBlc1swXT0i
anNvbiIsbz1lW2ldLGVbaV09ZnVuY3Rpb24oKXtzPWFyZ3VtZW50c30sci5hbHdheXMoZnVuY3Rp
b24oKXtlW2ldPW8sdFtpXSYmKHQuanNvbnBDYWxsYmFjaz1uLmpzb25wQ2FsbGJhY2ssaG4ucHVz
aChpKSkscyYmeC5pc0Z1bmN0aW9uKG8pJiZvKHNbMF0pLHM9bz11bmRlZmluZWR9KSwic2NyaXB0
Iik6dW5kZWZpbmVkfSkseC5hamF4U2V0dGluZ3MueGhyPWZ1bmN0aW9uKCl7dHJ5e3JldHVybiBu
ZXcgWE1MSHR0cFJlcXVlc3R9Y2F0Y2goZSl7fX07dmFyIGduPXguYWpheFNldHRpbmdzLnhocigp
LG1uPXswOjIwMCwxMjIzOjIwNH0seW49MCx2bj17fTtlLkFjdGl2ZVhPYmplY3QmJngoZSkub24o
InVubG9hZCIsZnVuY3Rpb24oKXtmb3IodmFyIGUgaW4gdm4pdm5bZV0oKTt2bj11bmRlZmluZWR9
KSx4LnN1cHBvcnQuY29ycz0hIWduJiYid2l0aENyZWRlbnRpYWxzImluIGduLHguc3VwcG9ydC5h
amF4PWduPSEhZ24seC5hamF4VHJhbnNwb3J0KGZ1bmN0aW9uKGUpe3ZhciB0O3JldHVybiB4LnN1
cHBvcnQuY29yc3x8Z24mJiFlLmNyb3NzRG9tYWluP3tzZW5kOmZ1bmN0aW9uKG4scil7dmFyIGks
byxzPWUueGhyKCk7aWYocy5vcGVuKGUudHlwZSxlLnVybCxlLmFzeW5jLGUudXNlcm5hbWUsZS5w
YXNzd29yZCksZS54aHJGaWVsZHMpZm9yKGkgaW4gZS54aHJGaWVsZHMpc1tpXT1lLnhockZpZWxk
c1tpXTtlLm1pbWVUeXBlJiZzLm92ZXJyaWRlTWltZVR5cGUmJnMub3ZlcnJpZGVNaW1lVHlwZShl
Lm1pbWVUeXBlKSxlLmNyb3NzRG9tYWlufHxuWyJYLVJlcXVlc3RlZC1XaXRoIl18fChuWyJYLVJl
cXVlc3RlZC1XaXRoIl09IlhNTEh0dHBSZXF1ZXN0Iik7Zm9yKGkgaW4gbilzLnNldFJlcXVlc3RI
ZWFkZXIoaSxuW2ldKTt0PWZ1bmN0aW9uKGUpe3JldHVybiBmdW5jdGlvbigpe3QmJihkZWxldGUg
dm5bb10sdD1zLm9ubG9hZD1zLm9uZXJyb3I9bnVsbCwiYWJvcnQiPT09ZT9zLmFib3J0KCk6ImVy
cm9yIj09PWU/cihzLnN0YXR1c3x8NDA0LHMuc3RhdHVzVGV4dCk6cihtbltzLnN0YXR1c118fHMu
c3RhdHVzLHMuc3RhdHVzVGV4dCwic3RyaW5nIj09dHlwZW9mIHMucmVzcG9uc2VUZXh0P3t0ZXh0
OnMucmVzcG9uc2VUZXh0fTp1bmRlZmluZWQscy5nZXRBbGxSZXNwb25zZUhlYWRlcnMoKSkpfX0s
cy5vbmxvYWQ9dCgpLHMub25lcnJvcj10KCJlcnJvciIpLHQ9dm5bbz15bisrXT10KCJhYm9ydCIp
LHMuc2VuZChlLmhhc0NvbnRlbnQmJmUuZGF0YXx8bnVsbCl9LGFib3J0OmZ1bmN0aW9uKCl7dCYm
dCgpfX06dW5kZWZpbmVkfSk7dmFyIHhuLGJuLHduPS9eKD86dG9nZ2xlfHNob3d8aGlkZSkkLyxU
bj1SZWdFeHAoIl4oPzooWystXSk9fCkoIitiKyIpKFthLXolXSopJCIsImkiKSxDbj0vcXVldWVI
b29rcyQvLGtuPVtBbl0sTm49eyIqIjpbZnVuY3Rpb24oZSx0KXt2YXIgbj10aGlzLmNyZWF0ZVR3
ZWVuKGUsdCkscj1uLmN1cigpLGk9VG4uZXhlYyh0KSxvPWkmJmlbM118fCh4LmNzc051bWJlcltl
XT8iIjoicHgiKSxzPSh4LmNzc051bWJlcltlXXx8InB4IiE9PW8mJityKSYmVG4uZXhlYyh4LmNz
cyhuLmVsZW0sZSkpLGE9MSx1PTIwO2lmKHMmJnNbM10hPT1vKXtvPW98fHNbM10saT1pfHxbXSxz
PStyfHwxO2RvIGE9YXx8Ii41IixzLz1hLHguc3R5bGUobi5lbGVtLGUscytvKTt3aGlsZShhIT09
KGE9bi5jdXIoKS9yKSYmMSE9PWEmJi0tdSl9cmV0dXJuIGkmJihuLnVuaXQ9byxuLnN0YXJ0PStz
fHwrcnx8MCxuLmVuZD1pWzFdP3MrKGlbMV0rMSkqaVsyXToraVsyXSksbn1dfTtmdW5jdGlvbiBF
bigpe3JldHVybiBzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7eG49dW5kZWZpbmVkfSkseG49eC5ub3co
KX1mdW5jdGlvbiBTbihlLHQsbil7dmFyIHIsaT0oTm5bdF18fFtdKS5jb25jYXQoTm5bIioiXSks
bz0wLHM9aS5sZW5ndGg7Zm9yKDtzPm87bysrKWlmKHI9aVtvXS5jYWxsKG4sdCxlKSlyZXR1cm4g
cn1mdW5jdGlvbiBqbihlLHQsbil7dmFyIHIsaSxvPTAscz1rbi5sZW5ndGgsYT14LkRlZmVycmVk
KCkuYWx3YXlzKGZ1bmN0aW9uKCl7ZGVsZXRlIHUuZWxlbX0pLHU9ZnVuY3Rpb24oKXtpZihpKXJl
dHVybiExO3ZhciB0PXhufHxFbigpLG49TWF0aC5tYXgoMCxsLnN0YXJ0VGltZStsLmR1cmF0aW9u
LXQpLHI9bi9sLmR1cmF0aW9ufHwwLG89MS1yLHM9MCx1PWwudHdlZW5zLmxlbmd0aDtmb3IoO3U+
cztzKyspbC50d2VlbnNbc10ucnVuKG8pO3JldHVybiBhLm5vdGlmeVdpdGgoZSxbbCxvLG5dKSwx
Pm8mJnU/bjooYS5yZXNvbHZlV2l0aChlLFtsXSksITEpfSxsPWEucHJvbWlzZSh7ZWxlbTplLHBy
b3BzOnguZXh0ZW5kKHt9LHQpLG9wdHM6eC5leHRlbmQoITAse3NwZWNpYWxFYXNpbmc6e319LG4p
LG9yaWdpbmFsUHJvcGVydGllczp0LG9yaWdpbmFsT3B0aW9uczpuLHN0YXJ0VGltZTp4bnx8RW4o
KSxkdXJhdGlvbjpuLmR1cmF0aW9uLHR3ZWVuczpbXSxjcmVhdGVUd2VlbjpmdW5jdGlvbih0LG4p
e3ZhciByPXguVHdlZW4oZSxsLm9wdHMsdCxuLGwub3B0cy5zcGVjaWFsRWFzaW5nW3RdfHxsLm9w
dHMuZWFzaW5nKTtyZXR1cm4gbC50d2VlbnMucHVzaChyKSxyfSxzdG9wOmZ1bmN0aW9uKHQpe3Zh
ciBuPTAscj10P2wudHdlZW5zLmxlbmd0aDowO2lmKGkpcmV0dXJuIHRoaXM7Zm9yKGk9ITA7cj5u
O24rKylsLnR3ZWVuc1tuXS5ydW4oMSk7cmV0dXJuIHQ/YS5yZXNvbHZlV2l0aChlLFtsLHRdKTph
LnJlamVjdFdpdGgoZSxbbCx0XSksdGhpc319KSxjPWwucHJvcHM7Zm9yKERuKGMsbC5vcHRzLnNw
ZWNpYWxFYXNpbmcpO3M+bztvKyspaWYocj1rbltvXS5jYWxsKGwsZSxjLGwub3B0cykpcmV0dXJu
IHI7cmV0dXJuIHgubWFwKGMsU24sbCkseC5pc0Z1bmN0aW9uKGwub3B0cy5zdGFydCkmJmwub3B0
cy5zdGFydC5jYWxsKGUsbCkseC5meC50aW1lcih4LmV4dGVuZCh1LHtlbGVtOmUsYW5pbTpsLHF1
ZXVlOmwub3B0cy5xdWV1ZX0pKSxsLnByb2dyZXNzKGwub3B0cy5wcm9ncmVzcykuZG9uZShsLm9w
dHMuZG9uZSxsLm9wdHMuY29tcGxldGUpLmZhaWwobC5vcHRzLmZhaWwpLmFsd2F5cyhsLm9wdHMu
YWx3YXlzKX1mdW5jdGlvbiBEbihlLHQpe3ZhciBuLHIsaSxvLHM7Zm9yKG4gaW4gZSlpZihyPXgu
Y2FtZWxDYXNlKG4pLGk9dFtyXSxvPWVbbl0seC5pc0FycmF5KG8pJiYoaT1vWzFdLG89ZVtuXT1v
WzBdKSxuIT09ciYmKGVbcl09byxkZWxldGUgZVtuXSkscz14LmNzc0hvb2tzW3JdLHMmJiJleHBh
bmQiaW4gcyl7bz1zLmV4cGFuZChvKSxkZWxldGUgZVtyXTtmb3IobiBpbiBvKW4gaW4gZXx8KGVb
bl09b1tuXSx0W25dPWkpfWVsc2UgdFtyXT1pfXguQW5pbWF0aW9uPXguZXh0ZW5kKGpuLHt0d2Vl
bmVyOmZ1bmN0aW9uKGUsdCl7eC5pc0Z1bmN0aW9uKGUpPyh0PWUsZT1bIioiXSk6ZT1lLnNwbGl0
KCIgIik7dmFyIG4scj0wLGk9ZS5sZW5ndGg7Zm9yKDtpPnI7cisrKW49ZVtyXSxObltuXT1Obltu
XXx8W10sTm5bbl0udW5zaGlmdCh0KX0scHJlZmlsdGVyOmZ1bmN0aW9uKGUsdCl7dD9rbi51bnNo
aWZ0KGUpOmtuLnB1c2goZSl9fSk7ZnVuY3Rpb24gQW4oZSx0LG4pe3ZhciByLGksbyxzLGEsdSxs
PXRoaXMsYz17fSxmPWUuc3R5bGUscD1lLm5vZGVUeXBlJiZMdChlKSxoPUguZ2V0KGUsImZ4c2hv
dyIpO24ucXVldWV8fChhPXguX3F1ZXVlSG9va3MoZSwiZngiKSxudWxsPT1hLnVucXVldWVkJiYo
YS51bnF1ZXVlZD0wLHU9YS5lbXB0eS5maXJlLGEuZW1wdHkuZmlyZT1mdW5jdGlvbigpe2EudW5x
dWV1ZWR8fHUoKX0pLGEudW5xdWV1ZWQrKyxsLmFsd2F5cyhmdW5jdGlvbigpe2wuYWx3YXlzKGZ1
bmN0aW9uKCl7YS51bnF1ZXVlZC0tLHgucXVldWUoZSwiZngiKS5sZW5ndGh8fGEuZW1wdHkuZmly
ZSgpfSl9KSksMT09PWUubm9kZVR5cGUmJigiaGVpZ2h0ImluIHR8fCJ3aWR0aCJpbiB0KSYmKG4u
b3ZlcmZsb3c9W2Yub3ZlcmZsb3csZi5vdmVyZmxvd1gsZi5vdmVyZmxvd1ldLCJpbmxpbmUiPT09
eC5jc3MoZSwiZGlzcGxheSIpJiYibm9uZSI9PT14LmNzcyhlLCJmbG9hdCIpJiYoZi5kaXNwbGF5
PSJpbmxpbmUtYmxvY2siKSksbi5vdmVyZmxvdyYmKGYub3ZlcmZsb3c9ImhpZGRlbiIsbC5hbHdh
eXMoZnVuY3Rpb24oKXtmLm92ZXJmbG93PW4ub3ZlcmZsb3dbMF0sZi5vdmVyZmxvd1g9bi5vdmVy
Zmxvd1sxXSxmLm92ZXJmbG93WT1uLm92ZXJmbG93WzJdfSkpO2ZvcihyIGluIHQpaWYoaT10W3Jd
LHduLmV4ZWMoaSkpe2lmKGRlbGV0ZSB0W3JdLG89b3x8InRvZ2dsZSI9PT1pLGk9PT0ocD8iaGlk
ZSI6InNob3ciKSl7aWYoInNob3ciIT09aXx8IWh8fGhbcl09PT11bmRlZmluZWQpY29udGludWU7
cD0hMH1jW3JdPWgmJmhbcl18fHguc3R5bGUoZSxyKX1pZigheC5pc0VtcHR5T2JqZWN0KGMpKXto
PyJoaWRkZW4iaW4gaCYmKHA9aC5oaWRkZW4pOmg9SC5hY2Nlc3MoZSwiZnhzaG93Iix7fSksbyYm
KGguaGlkZGVuPSFwKSxwP3goZSkuc2hvdygpOmwuZG9uZShmdW5jdGlvbigpe3goZSkuaGlkZSgp
fSksbC5kb25lKGZ1bmN0aW9uKCl7dmFyIHQ7SC5yZW1vdmUoZSwiZnhzaG93Iik7Zm9yKHQgaW4g
Yyl4LnN0eWxlKGUsdCxjW3RdKX0pO2ZvcihyIGluIGMpcz1TbihwP2hbcl06MCxyLGwpLHIgaW4g
aHx8KGhbcl09cy5zdGFydCxwJiYocy5lbmQ9cy5zdGFydCxzLnN0YXJ0PSJ3aWR0aCI9PT1yfHwi
aGVpZ2h0Ij09PXI/MTowKSl9fWZ1bmN0aW9uIExuKGUsdCxuLHIsaSl7cmV0dXJuIG5ldyBMbi5w
cm90b3R5cGUuaW5pdChlLHQsbixyLGkpfXguVHdlZW49TG4sTG4ucHJvdG90eXBlPXtjb25zdHJ1
Y3RvcjpMbixpbml0OmZ1bmN0aW9uKGUsdCxuLHIsaSxvKXt0aGlzLmVsZW09ZSx0aGlzLnByb3A9
bix0aGlzLmVhc2luZz1pfHwic3dpbmciLHRoaXMub3B0aW9ucz10LHRoaXMuc3RhcnQ9dGhpcy5u
b3c9dGhpcy5jdXIoKSx0aGlzLmVuZD1yLHRoaXMudW5pdD1vfHwoeC5jc3NOdW1iZXJbbl0/IiI6
InB4Iil9LGN1cjpmdW5jdGlvbigpe3ZhciBlPUxuLnByb3BIb29rc1t0aGlzLnByb3BdO3JldHVy
biBlJiZlLmdldD9lLmdldCh0aGlzKTpMbi5wcm9wSG9va3MuX2RlZmF1bHQuZ2V0KHRoaXMpfSxy
dW46ZnVuY3Rpb24oZSl7dmFyIHQsbj1Mbi5wcm9wSG9va3NbdGhpcy5wcm9wXTtyZXR1cm4gdGhp
cy5wb3M9dD10aGlzLm9wdGlvbnMuZHVyYXRpb24/eC5lYXNpbmdbdGhpcy5lYXNpbmddKGUsdGhp
cy5vcHRpb25zLmR1cmF0aW9uKmUsMCwxLHRoaXMub3B0aW9ucy5kdXJhdGlvbik6ZSx0aGlzLm5v
dz0odGhpcy5lbmQtdGhpcy5zdGFydCkqdCt0aGlzLnN0YXJ0LHRoaXMub3B0aW9ucy5zdGVwJiZ0
aGlzLm9wdGlvbnMuc3RlcC5jYWxsKHRoaXMuZWxlbSx0aGlzLm5vdyx0aGlzKSxuJiZuLnNldD9u
LnNldCh0aGlzKTpMbi5wcm9wSG9va3MuX2RlZmF1bHQuc2V0KHRoaXMpLHRoaXN9fSxMbi5wcm90
b3R5cGUuaW5pdC5wcm90b3R5cGU9TG4ucHJvdG90eXBlLExuLnByb3BIb29rcz17X2RlZmF1bHQ6
e2dldDpmdW5jdGlvbihlKXt2YXIgdDtyZXR1cm4gbnVsbD09ZS5lbGVtW2UucHJvcF18fGUuZWxl
bS5zdHlsZSYmbnVsbCE9ZS5lbGVtLnN0eWxlW2UucHJvcF0/KHQ9eC5jc3MoZS5lbGVtLGUucHJv
cCwiIiksdCYmImF1dG8iIT09dD90OjApOmUuZWxlbVtlLnByb3BdfSxzZXQ6ZnVuY3Rpb24oZSl7
eC5meC5zdGVwW2UucHJvcF0/eC5meC5zdGVwW2UucHJvcF0oZSk6ZS5lbGVtLnN0eWxlJiYobnVs
bCE9ZS5lbGVtLnN0eWxlW3guY3NzUHJvcHNbZS5wcm9wXV18fHguY3NzSG9va3NbZS5wcm9wXSk/
eC5zdHlsZShlLmVsZW0sZS5wcm9wLGUubm93K2UudW5pdCk6ZS5lbGVtW2UucHJvcF09ZS5ub3d9
fX0sTG4ucHJvcEhvb2tzLnNjcm9sbFRvcD1Mbi5wcm9wSG9va3Muc2Nyb2xsTGVmdD17c2V0OmZ1
bmN0aW9uKGUpe2UuZWxlbS5ub2RlVHlwZSYmZS5lbGVtLnBhcmVudE5vZGUmJihlLmVsZW1bZS5w
cm9wXT1lLm5vdyl9fSx4LmVhY2goWyJ0b2dnbGUiLCJzaG93IiwiaGlkZSJdLGZ1bmN0aW9uKGUs
dCl7dmFyIG49eC5mblt0XTt4LmZuW3RdPWZ1bmN0aW9uKGUscixpKXtyZXR1cm4gbnVsbD09ZXx8
ImJvb2xlYW4iPT10eXBlb2YgZT9uLmFwcGx5KHRoaXMsYXJndW1lbnRzKTp0aGlzLmFuaW1hdGUo
SG4odCwhMCksZSxyLGkpfX0pLHguZm4uZXh0ZW5kKHtmYWRlVG86ZnVuY3Rpb24oZSx0LG4scil7
cmV0dXJuIHRoaXMuZmlsdGVyKEx0KS5jc3MoIm9wYWNpdHkiLDApLnNob3coKS5lbmQoKS5hbmlt
YXRlKHtvcGFjaXR5OnR9LGUsbixyKX0sYW5pbWF0ZTpmdW5jdGlvbihlLHQsbixyKXt2YXIgaT14
LmlzRW1wdHlPYmplY3QoZSksbz14LnNwZWVkKHQsbixyKSxzPWZ1bmN0aW9uKCl7dmFyIHQ9am4o
dGhpcyx4LmV4dGVuZCh7fSxlKSxvKTtzLmZpbmlzaD1mdW5jdGlvbigpe3Quc3RvcCghMCl9LChp
fHxILmdldCh0aGlzLCJmaW5pc2giKSkmJnQuc3RvcCghMCl9O3JldHVybiBzLmZpbmlzaD1zLGl8
fG8ucXVldWU9PT0hMT90aGlzLmVhY2gocyk6dGhpcy5xdWV1ZShvLnF1ZXVlLHMpfSxzdG9wOmZ1
bmN0aW9uKGUsdCxuKXt2YXIgcj1mdW5jdGlvbihlKXt2YXIgdD1lLnN0b3A7ZGVsZXRlIGUuc3Rv
cCx0KG4pfTtyZXR1cm4ic3RyaW5nIiE9dHlwZW9mIGUmJihuPXQsdD1lLGU9dW5kZWZpbmVkKSx0
JiZlIT09ITEmJnRoaXMucXVldWUoZXx8ImZ4IixbXSksdGhpcy5lYWNoKGZ1bmN0aW9uKCl7dmFy
IHQ9ITAsaT1udWxsIT1lJiZlKyJxdWV1ZUhvb2tzIixvPXgudGltZXJzLHM9SC5nZXQodGhpcyk7
aWYoaSlzW2ldJiZzW2ldLnN0b3AmJnIoc1tpXSk7ZWxzZSBmb3IoaSBpbiBzKXNbaV0mJnNbaV0u
c3RvcCYmQ24udGVzdChpKSYmcihzW2ldKTtmb3IoaT1vLmxlbmd0aDtpLS07KW9baV0uZWxlbSE9
PXRoaXN8fG51bGwhPWUmJm9baV0ucXVldWUhPT1lfHwob1tpXS5hbmltLnN0b3AobiksdD0hMSxv
LnNwbGljZShpLDEpKTsodHx8IW4pJiZ4LmRlcXVldWUodGhpcyxlKX0pfSxmaW5pc2g6ZnVuY3Rp
b24oZSl7cmV0dXJuIGUhPT0hMSYmKGU9ZXx8ImZ4IiksdGhpcy5lYWNoKGZ1bmN0aW9uKCl7dmFy
IHQsbj1ILmdldCh0aGlzKSxyPW5bZSsicXVldWUiXSxpPW5bZSsicXVldWVIb29rcyJdLG89eC50
aW1lcnMscz1yP3IubGVuZ3RoOjA7Zm9yKG4uZmluaXNoPSEwLHgucXVldWUodGhpcyxlLFtdKSxp
JiZpLmN1ciYmaS5jdXIuZmluaXNoJiZpLmN1ci5maW5pc2guY2FsbCh0aGlzKSx0PW8ubGVuZ3Ro
O3QtLTspb1t0XS5lbGVtPT09dGhpcyYmb1t0XS5xdWV1ZT09PWUmJihvW3RdLmFuaW0uc3RvcCgh
MCksby5zcGxpY2UodCwxKSk7Zm9yKHQ9MDtzPnQ7dCsrKXJbdF0mJnJbdF0uZmluaXNoJiZyW3Rd
LmZpbmlzaC5jYWxsKHRoaXMpO2RlbGV0ZSBuLmZpbmlzaH0pfX0pO2Z1bmN0aW9uIEhuKGUsdCl7
dmFyIG4scj17aGVpZ2h0OmV9LGk9MDtmb3IodD10PzE6MDs0Pmk7aSs9Mi10KW49anRbaV0sclsi
bWFyZ2luIituXT1yWyJwYWRkaW5nIituXT1lO3JldHVybiB0JiYoci5vcGFjaXR5PXIud2lkdGg9
ZSkscn14LmVhY2goe3NsaWRlRG93bjpIbigic2hvdyIpLHNsaWRlVXA6SG4oImhpZGUiKSxzbGlk
ZVRvZ2dsZTpIbigidG9nZ2xlIiksZmFkZUluOntvcGFjaXR5OiJzaG93In0sZmFkZU91dDp7b3Bh
Y2l0eToiaGlkZSJ9LGZhZGVUb2dnbGU6e29wYWNpdHk6InRvZ2dsZSJ9fSxmdW5jdGlvbihlLHQp
e3guZm5bZV09ZnVuY3Rpb24oZSxuLHIpe3JldHVybiB0aGlzLmFuaW1hdGUodCxlLG4scil9fSks
eC5zcGVlZD1mdW5jdGlvbihlLHQsbil7dmFyIHI9ZSYmIm9iamVjdCI9PXR5cGVvZiBlP3guZXh0
ZW5kKHt9LGUpOntjb21wbGV0ZTpufHwhbiYmdHx8eC5pc0Z1bmN0aW9uKGUpJiZlLGR1cmF0aW9u
OmUsZWFzaW5nOm4mJnR8fHQmJiF4LmlzRnVuY3Rpb24odCkmJnR9O3JldHVybiByLmR1cmF0aW9u
PXguZngub2ZmPzA6Im51bWJlciI9PXR5cGVvZiByLmR1cmF0aW9uP3IuZHVyYXRpb246ci5kdXJh
dGlvbiBpbiB4LmZ4LnNwZWVkcz94LmZ4LnNwZWVkc1tyLmR1cmF0aW9uXTp4LmZ4LnNwZWVkcy5f
ZGVmYXVsdCwobnVsbD09ci5xdWV1ZXx8ci5xdWV1ZT09PSEwKSYmKHIucXVldWU9ImZ4Iiksci5v
bGQ9ci5jb21wbGV0ZSxyLmNvbXBsZXRlPWZ1bmN0aW9uKCl7eC5pc0Z1bmN0aW9uKHIub2xkKSYm
ci5vbGQuY2FsbCh0aGlzKSxyLnF1ZXVlJiZ4LmRlcXVldWUodGhpcyxyLnF1ZXVlKX0scn0seC5l
YXNpbmc9e2xpbmVhcjpmdW5jdGlvbihlKXtyZXR1cm4gZX0sc3dpbmc6ZnVuY3Rpb24oZSl7cmV0
dXJuLjUtTWF0aC5jb3MoZSpNYXRoLlBJKS8yfX0seC50aW1lcnM9W10seC5meD1Mbi5wcm90b3R5
cGUuaW5pdCx4LmZ4LnRpY2s9ZnVuY3Rpb24oKXt2YXIgZSx0PXgudGltZXJzLG49MDtmb3IoeG49
eC5ub3coKTt0Lmxlbmd0aD5uO24rKyllPXRbbl0sZSgpfHx0W25dIT09ZXx8dC5zcGxpY2Uobi0t
LDEpO3QubGVuZ3RofHx4LmZ4LnN0b3AoKSx4bj11bmRlZmluZWR9LHguZngudGltZXI9ZnVuY3Rp
b24oZSl7ZSgpJiZ4LnRpbWVycy5wdXNoKGUpJiZ4LmZ4LnN0YXJ0KCl9LHguZnguaW50ZXJ2YWw9
MTMseC5meC5zdGFydD1mdW5jdGlvbigpe2JufHwoYm49c2V0SW50ZXJ2YWwoeC5meC50aWNrLHgu
ZnguaW50ZXJ2YWwpKX0seC5meC5zdG9wPWZ1bmN0aW9uKCl7Y2xlYXJJbnRlcnZhbChibiksYm49
bnVsbH0seC5meC5zcGVlZHM9e3Nsb3c6NjAwLGZhc3Q6MjAwLF9kZWZhdWx0OjQwMH0seC5meC5z
dGVwPXt9LHguZXhwciYmeC5leHByLmZpbHRlcnMmJih4LmV4cHIuZmlsdGVycy5hbmltYXRlZD1m
dW5jdGlvbihlKXtyZXR1cm4geC5ncmVwKHgudGltZXJzLGZ1bmN0aW9uKHQpe3JldHVybiBlPT09
dC5lbGVtfSkubGVuZ3RofSkseC5mbi5vZmZzZXQ9ZnVuY3Rpb24oZSl7aWYoYXJndW1lbnRzLmxl
bmd0aClyZXR1cm4gZT09PXVuZGVmaW5lZD90aGlzOnRoaXMuZWFjaChmdW5jdGlvbih0KXt4Lm9m
ZnNldC5zZXRPZmZzZXQodGhpcyxlLHQpfSk7dmFyIHQsbixpPXRoaXNbMF0sbz17dG9wOjAsbGVm
dDowfSxzPWkmJmkub3duZXJEb2N1bWVudDtpZihzKXJldHVybiB0PXMuZG9jdW1lbnRFbGVtZW50
LHguY29udGFpbnModCxpKT8odHlwZW9mIGkuZ2V0Qm91bmRpbmdDbGllbnRSZWN0IT09ciYmKG89
aS5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKSksbj1xbihzKSx7dG9wOm8udG9wK24ucGFnZVlPZmZz
ZXQtdC5jbGllbnRUb3AsbGVmdDpvLmxlZnQrbi5wYWdlWE9mZnNldC10LmNsaWVudExlZnR9KTpv
fSx4Lm9mZnNldD17c2V0T2Zmc2V0OmZ1bmN0aW9uKGUsdCxuKXt2YXIgcixpLG8scyxhLHUsbCxj
PXguY3NzKGUsInBvc2l0aW9uIiksZj14KGUpLHA9e307InN0YXRpYyI9PT1jJiYoZS5zdHlsZS5w
b3NpdGlvbj0icmVsYXRpdmUiKSxhPWYub2Zmc2V0KCksbz14LmNzcyhlLCJ0b3AiKSx1PXguY3Nz
KGUsImxlZnQiKSxsPSgiYWJzb2x1dGUiPT09Y3x8ImZpeGVkIj09PWMpJiYobyt1KS5pbmRleE9m
KCJhdXRvIik+LTEsbD8ocj1mLnBvc2l0aW9uKCkscz1yLnRvcCxpPXIubGVmdCk6KHM9cGFyc2VG
bG9hdChvKXx8MCxpPXBhcnNlRmxvYXQodSl8fDApLHguaXNGdW5jdGlvbih0KSYmKHQ9dC5jYWxs
KGUsbixhKSksbnVsbCE9dC50b3AmJihwLnRvcD10LnRvcC1hLnRvcCtzKSxudWxsIT10LmxlZnQm
JihwLmxlZnQ9dC5sZWZ0LWEubGVmdCtpKSwidXNpbmciaW4gdD90LnVzaW5nLmNhbGwoZSxwKTpm
LmNzcyhwKX19LHguZm4uZXh0ZW5kKHtwb3NpdGlvbjpmdW5jdGlvbigpe2lmKHRoaXNbMF0pe3Zh
ciBlLHQsbj10aGlzWzBdLHI9e3RvcDowLGxlZnQ6MH07cmV0dXJuImZpeGVkIj09PXguY3NzKG4s
InBvc2l0aW9uIik/dD1uLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOihlPXRoaXMub2Zmc2V0UGFy
ZW50KCksdD10aGlzLm9mZnNldCgpLHgubm9kZU5hbWUoZVswXSwiaHRtbCIpfHwocj1lLm9mZnNl
dCgpKSxyLnRvcCs9eC5jc3MoZVswXSwiYm9yZGVyVG9wV2lkdGgiLCEwKSxyLmxlZnQrPXguY3Nz
KGVbMF0sImJvcmRlckxlZnRXaWR0aCIsITApKSx7dG9wOnQudG9wLXIudG9wLXguY3NzKG4sIm1h
cmdpblRvcCIsITApLGxlZnQ6dC5sZWZ0LXIubGVmdC14LmNzcyhuLCJtYXJnaW5MZWZ0IiwhMCl9
fX0sb2Zmc2V0UGFyZW50OmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMubWFwKGZ1bmN0aW9uKCl7dmFy
IGU9dGhpcy5vZmZzZXRQYXJlbnR8fHM7d2hpbGUoZSYmIXgubm9kZU5hbWUoZSwiaHRtbCIpJiYi
c3RhdGljIj09PXguY3NzKGUsInBvc2l0aW9uIikpZT1lLm9mZnNldFBhcmVudDtyZXR1cm4gZXx8
c30pfX0pLHguZWFjaCh7c2Nyb2xsTGVmdDoicGFnZVhPZmZzZXQiLHNjcm9sbFRvcDoicGFnZVlP
ZmZzZXQifSxmdW5jdGlvbih0LG4pe3ZhciByPSJwYWdlWU9mZnNldCI9PT1uO3guZm5bdF09ZnVu
Y3Rpb24oaSl7cmV0dXJuIHguYWNjZXNzKHRoaXMsZnVuY3Rpb24odCxpLG8pe3ZhciBzPXFuKHQp
O3JldHVybiBvPT09dW5kZWZpbmVkP3M/c1tuXTp0W2ldOihzP3Muc2Nyb2xsVG8ocj9lLnBhZ2VY
T2Zmc2V0Om8scj9vOmUucGFnZVlPZmZzZXQpOnRbaV09byx1bmRlZmluZWQpfSx0LGksYXJndW1l
bnRzLmxlbmd0aCxudWxsKX19KTtmdW5jdGlvbiBxbihlKXtyZXR1cm4geC5pc1dpbmRvdyhlKT9l
Ojk9PT1lLm5vZGVUeXBlJiZlLmRlZmF1bHRWaWV3fXguZWFjaCh7SGVpZ2h0OiJoZWlnaHQiLFdp
ZHRoOiJ3aWR0aCJ9LGZ1bmN0aW9uKGUsdCl7eC5lYWNoKHtwYWRkaW5nOiJpbm5lciIrZSxjb250
ZW50OnQsIiI6Im91dGVyIitlfSxmdW5jdGlvbihuLHIpe3guZm5bcl09ZnVuY3Rpb24ocixpKXt2
YXIgbz1hcmd1bWVudHMubGVuZ3RoJiYobnx8ImJvb2xlYW4iIT10eXBlb2Ygcikscz1ufHwocj09
PSEwfHxpPT09ITA/Im1hcmdpbiI6ImJvcmRlciIpO3JldHVybiB4LmFjY2Vzcyh0aGlzLGZ1bmN0
aW9uKHQsbixyKXt2YXIgaTtyZXR1cm4geC5pc1dpbmRvdyh0KT90LmRvY3VtZW50LmRvY3VtZW50
RWxlbWVudFsiY2xpZW50IitlXTo5PT09dC5ub2RlVHlwZT8oaT10LmRvY3VtZW50RWxlbWVudCxN
YXRoLm1heCh0LmJvZHlbInNjcm9sbCIrZV0saVsic2Nyb2xsIitlXSx0LmJvZHlbIm9mZnNldCIr
ZV0saVsib2Zmc2V0IitlXSxpWyJjbGllbnQiK2VdKSk6cj09PXVuZGVmaW5lZD94LmNzcyh0LG4s
cyk6eC5zdHlsZSh0LG4scixzKX0sdCxvP3I6dW5kZWZpbmVkLG8sbnVsbCl9fSl9KSx4LmZuLnNp
emU9ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5sZW5ndGh9LHguZm4uYW5kU2VsZj14LmZuLmFkZEJh
Y2ssIm9iamVjdCI9PXR5cGVvZiBtb2R1bGUmJm1vZHVsZSYmIm9iamVjdCI9PXR5cGVvZiBtb2R1
bGUuZXhwb3J0cz9tb2R1bGUuZXhwb3J0cz14OiJmdW5jdGlvbiI9PXR5cGVvZiBkZWZpbmUmJmRl
ZmluZS5hbWQmJmRlZmluZSgianF1ZXJ5IixbXSxmdW5jdGlvbigpe3JldHVybiB4fSksIm9iamVj
dCI9PXR5cGVvZiBlJiYib2JqZWN0Ij09dHlwZW9mIGUuZG9jdW1lbnQmJihlLmpRdWVyeT1lLiQ9
eCl9KSh3aW5kb3cpOwo=

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

Version 0.06

=head1 SYNOPSIS

This command generate an application with a DBIx::Class model and a simple authentication controller.

To generate an app run:

    mojo generate bootstrap_app My::Bootstrap::App

This will create the directory structure with a default YAML config and basic testing.

    cd my_bootstrap_app

To get database version and migration management you should install DBIx::Class::Migration (>= 0.038).

The default database is an SQLite database that gets installed into share/my_bootstrap_app.db. If you would like to change the database edit your config.yml accordingly.

If installed you can use script/migration as a thin wrapper around dbic-migration setting lib and the correct database already.
Running:

    script/migrate prepare
    script/migrate install
    script/migrate populate

Prepare generates the SQL files needed, install actually creates the database schema and populate will populate the database with the data from share/fixtures. So edit those to customize the default user.

If you do not have and do not want DBIx::Class::Migrate you can initialize the database with:

    script/migrate --init

Now run the test to check if everything went right.

    script/my_bootstrap_app test

=head1 FILES

The file structure generated is very similar to the non lite app with a few differences:

    |-- config.yml                                     => your applications config file
    |                                                     contains the database connection details and more
    |-- lib
    |   `-- My
    |       `-- Bootstrap
    |           |-- App
    |           |   |-- Controller                     => authentication related controllers
    |           |   |   |-- Auth.pm
    |           |   |   |-- Example.pm
    |           |   |   `-- Users.pm
    |           |   |-- Controller.pm                  => the application controller
    |           |   |                                     all controllers inherit from this
    |           |   |                                     so application wide controller code goes here
    |           |   |-- DB                             => the basic database
    |           |   |   `-- Result                        including a User result class used for authentication
    |           |   |       `-- User.pm
    |           |   `-- DB.pm
    |           `-- App.pm
    |-- public
    |   |-- bootstrap                                  => Twitter Bootstrap
    |   |   |-- css
    |   |   |   |-- bootstrap.min.css
    |   |   |   `-- bootstrap-responsive.min.css
    |   |   |-- img
    |   |   |   |-- glyphicons-halflings.png
    |   |   |   `-- glyphicons-halflings-white.png
    |   |   `-- js
    |   |       |-- bootstrap.min.js
    |   |       `-- jquery.min.js                      => jQuery to make modals, dropdowns, etc. work
    |   |-- index.html
    |   `-- style.css
    |-- script
    |   |-- migrate                                    => migration script using DBIx::Class::Migration
    |   `-- my_bootstrap_app
    |-- share                                          => fixtures for the default admin user
    |   |-- development                                   structure for three modes prepared
    |   |   `-- fixtures                                  you can add as many as you need
    |   |       `-- 1
    |   |           |-- all_tables
    |   |           |   `-- users
    |   |           |       `-- 1.fix
    |   |           `-- conf
    |   |               `-- all_tables.json
    |   |-- production
    |   |   `-- fixtures
    |   |       `-- 1
    |   |           |-- all_tables
    |   |           |   `-- users
    |   |           |       `-- 1.fix
    |   |           `-- conf
    |   |               `-- all_tables.json
    |   `-- testing
    |       `-- fixtures
    |           `-- 1
    |               |-- all_tables
    |               |   `-- users
    |               |       `-- 1.fix
    |               `-- conf
    |                   `-- all_tables.json
    |-- t
    |   `-- basic.t
    `-- templates                                      => templates to make use of the authentication
        |-- auth
        |   `-- login.html.ep
        |-- elements                                   => configure key elements of the site seperatly from
        |   |-- flash.html.ep                             the main layout
        |   |-- footer.html.ep
        |   `-- topnav.html.ep
        |-- example
        |   `-- welcome.html.ep
        |-- layouts
        |   `-- bootstrap.html.ep
        `-- users
            |-- add.html.ep
            |-- edit.html.ep
            `-- list.html.ep

=head1 AUTHOR

Matthias Krull, C<< <m.krull at uninets.eu> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-mojolicious-command-generate-bootstrap_app at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Mojolicious-Command-generate-bootstrap_app>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

Alternatively file an issue at the github repo:

L<https://github.com/mkrull/Mojolicious-Command-generate-bootstrap_app/issues>


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

L<https://github.com/mkrull/Mojolicious-Command-generate-bootstrap_app/>

=back


=head1 LICENSE AND COPYRIGHT

=head2 Bootstrap

L<http://www.apache.org/licenses/LICENSE-2.0>

L<https://github.com/twitter/bootstrap/wiki/License>

=head2 jQuery

Copyright 2013 jQuery Foundation and other contributors
http://jquery.com/

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

=head2 Generator

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

