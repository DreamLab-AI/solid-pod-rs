#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
base_url=${CTH_BASE_URL:-http://127.0.0.1:4000}
target=${CTH_TARGET:-https://github.com/solid/conformance-test-harness/solid-pod-rs}
image=${CTH_IMAGE:-solidproject/conformance-test-harness:latest}
subjects="$repo_root/scripts/cth/test-subjects.ttl"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
curl -fsS "$base_url/.well-known/openid-configuration" >/dev/null || {
  echo "No server with Solid-OIDC discovery is reachable at $base_url" >&2
  exit 2
}

docker run --rm --network=host \
  -v "$subjects:/app/test-subjects.ttl:ro" \
  -e "SUBJECTS=/app/test-subjects.ttl" \
  -e "SERVER_ROOT=$base_url" \
  -e "RESOURCE_SERVER_ROOT=$base_url" \
  -e "SOLID_IDENTITY_PROVIDER=$base_url/" \
  "$image" --target="$target" "$@"
