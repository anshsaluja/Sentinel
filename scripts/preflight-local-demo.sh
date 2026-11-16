#!/usr/bin/env bash
# Read-only prerequisites check for the host-run Sentinel demo.
set -uo pipefail
if [[ "${1:-}" == "--help" && $# -eq 1 ]]; then
  echo "Usage: bash scripts/preflight-local-demo.sh [--services]"
  exit 0
fi
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--services" ) ]]; then
  echo "Usage: bash scripts/preflight-local-demo.sh [--services]" >&2
  exit 2
fi
failures=0
check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS $label";
  else echo "FAIL $label" >&2; failures=$((failures + 1)); fi
}
check "Java 21" bash -c 'java -version 2>&1 | head -n 1 | grep -Eq "version \"21[.\"]|openjdk 21"'
check "Maven" command -v mvn
check "Node.js 22" bash -c 'node -p "process.versions.node.split(String.fromCharCode(46))[0]" | grep -qx 22'
check "npm" command -v npm
check "Docker Compose" docker compose version
check "Docker daemon" docker info
if [[ "${1:-}" == "--services" ]]; then
  check "MongoDB replica set primary" docker exec "$(docker compose ps -q mongodb)" mongosh --quiet --eval 'quit(db.hello().isWritablePrimary ? 0 : 1)'
  check "Keycloak OIDC discovery" curl --fail --silent --show-error --max-time 5 http://localhost:8081/realms/sentinel/.well-known/openid-configuration
fi
if (( failures )); then
  echo "$failures prerequisite check(s) failed; application tests were not run." >&2
  exit 1
fi
echo "Prerequisites passed; run application tests and authenticated demo separately."
