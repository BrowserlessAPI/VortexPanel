#!/bin/bash
# OpenLiteSpeed is installed into /usr/local/lsws by its own installer (activate.sh).
. "$(dirname "$0")/lib.sh"
set -e
# a LiteSpeed-repository install is switched over by the engine (VP_ACTION=migrate): its
# package is already removed here and /usr/local/lsws/conf, admin/conf are back as they were
true
