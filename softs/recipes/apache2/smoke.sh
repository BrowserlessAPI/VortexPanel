#!/bin/bash
set -e
curl -fsS -o /dev/null http://127.0.0.1/ || { echo "Apache does not answer on port 80"; exit 1; }
apachectl configtest 2>&1 | grep -q 'Syntax OK'
if [ -d /etc/apache2 ]; then
  a2enmod -q rewrite headers proxy_fcgi >/dev/null
  a2query -m rewrite | grep -q enabled
  a2query -m proxy | grep -q enabled          # dependency of proxy_fcgi
  apache2ctl configtest 2>&1 | grep -q 'Syntax OK'
  a2dismod -q headers >/dev/null; ! a2query -q -m headers
fi
echo "Apache smoke test passed"
