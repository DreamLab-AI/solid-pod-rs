#!/usr/bin/env bash
# RES-c diagram staleness guard.
#
# Fails when a Mermaid source under docs/diagrams/src/ is newer than its
# rendered output under docs/diagrams/rendered/ — the exact drift the RES-c
# item exists to close (8/9 PNGs were stale against their .mmd sources, and
# one was missing). "Newer" is measured by git commit time, with a working-
# tree fallback so the guard also catches an edited-but-not-re-rendered source
# before it is committed (pre-commit use):
#
#   effective_time(f) = mtime(f)             if f is untracked or dirty
#                     = last commit epoch    otherwise
#
# A source committed together with its render shares a commit, so the times
# are equal and the guard passes. Edit the source alone and it becomes newer
# than the render → the guard fails until the render is regenerated with
# scripts/diagram-render (the VisionFlow canon renderer, RES-b gate).
#
# Every source must have BOTH a rendered .svg (the RES-b text-visibility gate
# format) and a .png; a missing render is treated as maximally stale so an
# unrendered diagram (the old diagram 9) fails the guard.
#
# Pure git + coreutils; no browser, no npm — runs in CI without the sidecar.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/crates/solid-pod-rs/docs/diagrams/src"
RENDER_DIR="$REPO_ROOT/crates/solid-pod-rs/docs/diagrams/rendered"

# Effective modification epoch: working-tree mtime if the path is untracked or
# has uncommitted changes, otherwise the last commit's author epoch.
effective_time() {
  local f="$1"
  if [[ ! -e "$f" ]]; then
    echo 0
    return
  fi
  local rel status commit_ct
  rel="$(git -C "$REPO_ROOT" ls-files --error-unmatch "$f" 2>/dev/null || true)"
  if [[ -z "$rel" ]]; then
    # Untracked: use filesystem mtime.
    stat -c %Y "$f"
    return
  fi
  status="$(git -C "$REPO_ROOT" status --porcelain -- "$f")"
  if [[ -n "$status" ]]; then
    # Tracked but dirty: the working copy is what matters.
    stat -c %Y "$f"
    return
  fi
  commit_ct="$(git -C "$REPO_ROOT" log -1 --format=%ct -- "$f" 2>/dev/null || true)"
  echo "${commit_ct:-0}"
}

fail=0
count=0
shopt -s nullglob
for src in "$SRC_DIR"/*.mmd; do
  count=$((count + 1))
  base="$(basename "${src%.mmd}")"
  src_t="$(effective_time "$src")"
  for ext in svg png; do
    out="$RENDER_DIR/$base.$ext"
    if [[ ! -e "$out" ]]; then
      echo "  STALE  $base.$ext: missing render for src/$base.mmd"
      fail=$((fail + 1))
      continue
    fi
    out_t="$(effective_time "$out")"
    if (( src_t > out_t )); then
      echo "  STALE  $base.$ext: src/$base.mmd ($src_t) is newer than rendered/$base.$ext ($out_t)"
      fail=$((fail + 1))
    else
      echo "  ok     $base.$ext: up to date"
    fi
  done
done

if (( count == 0 )); then
  echo "no .mmd sources under $SRC_DIR"
  exit 1
fi
if (( fail > 0 )); then
  echo ""
  echo "$fail rendered diagram(s) stale or missing. Re-render with the canon"
  echo "renderer (VisionFlow scripts/diagram-render) and commit src + rendered together."
  exit 1
fi
echo ""
echo "All $count diagram source(s) current against their rendered .svg + .png."
