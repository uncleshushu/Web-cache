
create table users
(
    name varchar(20) primary key,
    passwd_hash varchar(20),
    rule_path varchar(200)
);

create table caches
(
    uri varchar(2000) primary key,
    last_modified varchar(30),
    path varchar(255)
);

