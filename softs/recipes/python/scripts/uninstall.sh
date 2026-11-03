#!/bin/bash
. "$(dirname "$0")/lib.sh"
V="$VP_TRACK"
unlink_ours "/usr/local/bin/python$V"; unlink_ours "/usr/local/bin/pip$V"
