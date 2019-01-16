#!/usr/bin/env sh

rm -rf caches/*

sqlite3 proxy_db.db 'drop table caches;'

sqlite3 proxy_db.db < init.sql


