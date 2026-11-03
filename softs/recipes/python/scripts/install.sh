#!/bin/bash
# Python X.Y into /usr/local/bin only: the operating system's own /usr/bin/python3* is never touched.
. "$(dirname "$0")/lib.sh"
set -e
V="$VP_TRACK"
link "$VP_CURRENT/bin/python$V" "/usr/local/bin/python$V"
link "$VP_CURRENT/bin/pip$V" "/usr/local/bin/pip$V"
