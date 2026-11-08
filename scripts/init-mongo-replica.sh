#!/usr/bin/env bash
# Initialize the local MongoDB single-node replica set required by transactions.
# Run from the repository root after: docker compose up -d mongodb
set -euo pipefail

docker compose exec -T mongodb mongosh --quiet --eval '
const admin = db.getSiblingDB("admin");
const status = admin.runCommand({ replSetGetStatus: 1 });
if (status.ok === 1) {
  print("Replica set already initialized.");
} else if (status.code === 94 || status.codeName === "NotYetInitialized") {
  const result = rs.initiate({
    _id: "rs0",
    members: [{ _id: 0, host: "localhost:27017" }]
  });
  if (result.ok !== 1) {
    printjson(result);
    quit(1);
  }
  print("Replica set initiated.");
} else {
  printjson(status);
  quit(1);
}
'
# Wait for primary election; fail rather than reporting an unready database.
for attempt in $(seq 1 30); do
  if docker compose exec -T mongodb mongosh --quiet --eval     'quit(db.hello().isWritablePrimary ? 0 : 1)' >/dev/null 2>&1; then
    echo "MongoDB rs0 primary ready for local transactions."
    exit 0
  fi
  sleep 1
done
echo "MongoDB replica set did not elect a primary within 30 seconds." >&2
exit 1
