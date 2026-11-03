#!/bin/bash
set -e
printf 'SecRuleEngine On\nSecRule ARGS "@contains attack" "id:1001,phase:2,deny,status:403"\n' > /tmp/vp-modsec-smoke.conf
modsec-rules-check /tmp/vp-modsec-smoke.conf
ldconfig -p | grep -q '/usr/local/vortex/libmodsecurity/current/lib/libmodsecurity.so.3'
echo "libmodsecurity smoke test passed"
