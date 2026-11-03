#!/bin/bash
# root logs in over the socket without a password (auth_socket), like the panel does
set -e
mysql -NBe "CREATE DATABASE IF NOT EXISTS vp_smoke; CREATE TABLE IF NOT EXISTS vp_smoke.t (a INT);
            INSERT INTO vp_smoke.t VALUES (42); SELECT a FROM vp_smoke.t" | grep -qx 42
mysqldump vp_smoke >/dev/null
mysql -e "DROP DATABASE vp_smoke"
echo "MySQL smoke test passed"
