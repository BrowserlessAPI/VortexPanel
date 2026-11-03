#!/bin/bash
set -e
[ "$(node -e 'console.log(1+1)')" = 2 ] && echo "Node.js smoke test passed"
