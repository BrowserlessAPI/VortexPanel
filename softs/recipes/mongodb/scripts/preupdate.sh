#!/bin/bash
# Before another version opens the data: stop the server and keep a copy of the data.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/mongo_common.sh"
has_systemd || stop_direct
data_backup "$(dbpath)" mongod
