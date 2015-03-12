requires 'Crypt::Passwd::XS';
requires 'DBIx::Class';
requires 'DBIx::Connector';
requires 'Email::Valid';
requires 'Mojolicious', '6';
requires 'String::Random';
requires 'YAML';

on build => sub {
    requires 'Test::More';
};
