#!/bin/bash
. "$(dirname "$0")/lib.sh"
set -e
link "$VP_CURRENT/bin/composer" /usr/local/bin/composer
