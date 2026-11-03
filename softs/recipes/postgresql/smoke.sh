#!/bin/bash
# the postgres system user signs in over the local socket (peer), like the panel does
set -e
q() { runuser -u postgres -- psql -XAtq -c "$1"; }
q "CREATE DATABASE vp_smoke" 
runuser -u postgres -- psql -XAtq -d vp_smoke -c "CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE TABLE t (a int); INSERT INTO t VALUES (42)"
[ "$(runuser -u postgres -- psql -XAt -d vp_smoke -c 'SELECT a FROM t')" = 42 ]
runuser -u postgres -- pg_dump vp_smoke >/dev/null
q "DROP DATABASE vp_smoke"
echo "PostgreSQL smoke test passed"
