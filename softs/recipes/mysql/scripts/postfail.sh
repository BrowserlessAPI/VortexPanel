#!/bin/bash
# The new version failed: put the data copy back for the previous version.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
has_systemd || stop_direct
data_restore "$(datadir)" mysql
