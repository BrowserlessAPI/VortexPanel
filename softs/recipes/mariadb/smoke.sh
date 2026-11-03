#!/bin/bash
# root logs in over the socket without a password (unix_socket), like the panel does
set -e
mariadb -NBe "CREATE DATABASE IF NOT EXISTS vp_smoke; CREATE TABLE IF NOT EXISTS vp_smoke.t (a INT);
              INSERT INTO vp_smoke.t VALUES (42); SELECT a FROM vp_smoke.t" | grep -qx 42
mariadb-dump vp_smoke >/dev/null
mariadb -e "DROP DATABASE vp_smoke"
echo "MariaDB smoke test passed"
