# Shared by the MongoDB scripts (sourced after lib.sh).
CONF=/etc/mongod.conf
# value of a "key: value" line in mongod.conf (the panel's and MongoDB's own layout)
yval() { [ -f "$CONF" ] && sed -nE "s/^[[:space:]]*$1:[[:space:]]*['\"]?([^'\"#[:space:]]+).*/\1/p" "$CONF" | head -1; }
dbpath() {
  local d; d="$(yval dbPath)"
  if [ -n "$d" ]; then echo "$d"; elif [ "${VP_FAMILY:-deb}" = rpm ]; then echo /var/lib/mongo; else echo /var/lib/mongodb; fi
}
# the account mongod runs as: the owner of an existing data folder, else mongodb (deb) / mongod (rpm)
muser() {
  local d o; d="$(dbpath)"
  if [ -d "$d" ]; then o="$(stat -c %U "$d")"; [ "$o" != root ] && [ "$o" != UNKNOWN ] && { echo "$o"; return; }; fi
  if [ "${VP_FAMILY:-deb}" = rpm ]; then echo mongod; else echo mongodb; fi
}
mport() { local p; p="$(yval port)"; echo "${p:-27017}"; }
mongod_pids() { pgrep -x mongod 2>/dev/null; }
stop_direct() {
  local i p; p="$(mongod_pids)"; [ -n "$p" ] || return 0
  kill -TERM $p 2>/dev/null
  for i in $(seq 1 120); do [ -z "$(mongod_pids)" ] && return 0; sleep 1; done
  kill -KILL $(mongod_pids) 2>/dev/null; true
}
