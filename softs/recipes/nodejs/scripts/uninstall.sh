#!/bin/bash
. "$(dirname "$0")/lib.sh"
for b in node npm npx corepack; do unlink_ours "/usr/bin/$b"; done
