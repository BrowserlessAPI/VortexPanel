#!/bin/bash
set -e
out="$(mongosh --quiet --eval 'db.getSiblingDB("vp_smoke").t.insertOne({a:42}); print(db.getSiblingDB("vp_smoke").t.findOne().a); db.getSiblingDB("vp_smoke").dropDatabase()')"
echo "$out" | grep -qx 42
echo "MongoDB smoke test passed"
