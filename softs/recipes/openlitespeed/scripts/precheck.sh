#!/bin/bash
# Checked before anything on the server changes.
. "$(dirname "$0")/lib.sh"
[ ! -f /usr/local/lsws/conf/httpd_config.xml ] || fail "this server has a pre-1.4 OpenLiteSpeed XML configuration; convert it first"
true
