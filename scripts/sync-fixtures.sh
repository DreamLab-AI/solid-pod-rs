#!/usr/bin/env bash
# scripts/sync-fixtures.sh — solid-pod-rs substrate
#
# Per ADR-082 D5: solid-pod-rs consumes cross-substrate fixtures from VisionClaw
# (the master host). This script copies docs/specs/fixtures/ into the relevant
# crate test directories and writes CHECKSUM.txt for CI drift detection.
#
# solid-pod-rs has two crates consuming fixtures:
#   - solid-pod-rs-nostr  (NIP-01, NIP-19, NIP-98, BIP-340, RFC-8785,
#                           Multibase, DID-doc, IS-Envelope)
#   - solid-pod-rs-didkey (DID-doc, BIP-340, Multibase)
#
# Usage:
#   scripts/sync-fixtures.sh                    # full sync
#   scripts/sync-fixtures.sh --verify           # CI gate: exit non-zero on drift
#   VISIONCLAW_FIXTURES_PATH=/local/path \
#     scripts/sync-fixtures.sh                  # offline / local-monorepo dev
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${VISIONCLAW_FIXTURES_PATH:-https://github.com/DreamLab-AI/VisionClaw.git}"

# Target directories for each consuming crate
NOSTR_TARGET="$REPO_ROOT/crates/solid-pod-rs-nostr/tests/fixtures"
DIDKEY_TARGET="$REPO_ROOT/crates/solid-pod-rs-didkey/tests/fixtures"

case "${1:-}" in
  --verify)
    FAIL=0
    for TARGET in "$NOSTR_TARGET" "$DIDKEY_TARGET"; do
      CRATE="$(basename "$(dirname "$(dirname "$TARGET")")")"
      if [ ! -f "$TARGET/CHECKSUM.txt" ]; then
        echo "ERROR: $TARGET/CHECKSUM.txt missing — run sync-fixtures.sh first" >&2
        FAIL=1
        continue
      fi
      cd "$TARGET"
      if sha256sum -c CHECKSUM.txt --quiet; then
        echo "OK ($CRATE): $(wc -l < CHECKSUM.txt) fixture file(s) match recorded checksums."
      else
        echo "ERROR ($CRATE): checksum mismatch" >&2
        FAIL=1
      fi
    done
    exit "$FAIL"
    ;;
esac

# Fetch master fixtures.
if [[ "$SOURCE" =~ ^https://.*\.git$ ]]; then
  TMPDIR=$(mktemp -d)
  trap "rm -rf $TMPDIR" EXIT
  git clone --depth=1 --filter=blob:none --sparse --quiet "$SOURCE" "$TMPDIR"
  (cd "$TMPDIR" && git sparse-checkout add docs/specs/fixtures)
  FIXTURE_SRC="$TMPDIR/docs/specs/fixtures"
else
  if [ ! -d "$SOURCE/docs/specs/fixtures" ]; then
    echo "ERROR: VISIONCLAW_FIXTURES_PATH=$SOURCE has no docs/specs/fixtures/" >&2
    exit 1
  fi
  FIXTURE_SRC="$SOURCE/docs/specs/fixtures"
fi

# Sync to both crate test dirs.
for TARGET in "$NOSTR_TARGET" "$DIDKEY_TARGET"; do
  mkdir -p "$TARGET"
  if command -v rsync &>/dev/null; then
    rsync -a --delete --exclude='CHECKSUM.txt' \
      "$FIXTURE_SRC/" "$TARGET/"
  else
    rm -rf "$TARGET"/*.json "$TARGET"/*.md "$TARGET"/*.txt "$TARGET"/schemas 2>/dev/null
    mkdir -p "$TARGET/schemas"
    cp -a "$FIXTURE_SRC/"*.json "$FIXTURE_SRC/"*.md "$FIXTURE_SRC/"*.txt "$TARGET/" 2>/dev/null || true
    cp -a "$FIXTURE_SRC/schemas/"* "$TARGET/schemas/" 2>/dev/null || true
  fi
  cd "$TARGET"
  sha256sum *.json README.md UPSTREAM_PINS.md COVERAGE_MATRIX.md \
    $(find schemas -type f 2>/dev/null) > CHECKSUM.txt
  CRATE="$(basename "$(dirname "$(dirname "$TARGET")")")"
  echo "Synced $(wc -l < CHECKSUM.txt) fixture file(s) into $TARGET ($CRATE)"
done

echo "Run 'scripts/sync-fixtures.sh --verify' in CI to detect drift."
