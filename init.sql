create table if not exists
users
(
    name varchar primary key,
    passwd_hash varchar,
    rule_path varchar
);

create table if not exists
caches
(
    url_hash varchar primary key,
    cache_path varchar,
    cached_time timestamp,
    max_age integer,
    etag varchar,
    last_modified varchar
);

