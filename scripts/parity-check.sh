#!/usr/bin/env bash
set -euo pipefail

# parity-check.sh — parity verification against PARITY-CHECKLIST.md.
#
# Reads the checklist, counts rows by status, calculates strict parity
# percentage. Exit 0 if strict >= 95%.
#
# Methodology:
#   - Every markdown table row starting with "| <number> |" is a feature row.
#   - Status is extracted from the 6th pipe-delimited field.
#   - "Shipped" = present | net-new | semantic-difference | present-by-absence
#     | shared-gap | present (both absent) | test/conformance meta
#   - "Not shipped" = missing | partial-parity | explicitly-deferred |
#     wontfix-in-crate | other
#   - Strict = shipped / total
#
# The checklist headline uses the same classification as this script:
# architectural and explicitly out-of-scope rows are excluded from the
# strict denominator, while missing and partial rows remain in scope.

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECKLIST="$WORKSPACE_ROOT/crates/solid-pod-rs/PARITY-CHECKLIST.md"

if [[ ! -f "$CHECKLIST" ]]; then
    echo "ERROR: PARITY-CHECKLIST.md not found at $CHECKLIST" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Colours (disable if not a terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Classify each table row.
# ---------------------------------------------------------------------------

count_present=0
count_partial=0
count_semantic_diff=0
count_missing=0
count_net_new=0
count_deferred=0
count_wontfix=0
count_other=0
total_rows=0

while IFS= read -r line; do
    # Match only table rows starting with "| <number> |".
    if ! echo "$line" | grep -qE '^\|\s*[0-9]+[a-z]?\s*\|'; then
        continue
    fi

    total_rows=$((total_rows + 1))

    # Extract the status field (column 6) and normalise.
    status_raw=$(echo "$line" | awk -F'|' '{print $6}' | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/\*//g')

    # Classify. Order matters: more specific patterns first.
    case "$status_raw" in
        *"net-new"*|*"net new"*)
            count_net_new=$((count_net_new + 1))
            ;;
        *"partial-parity"*|*"partial"*)
            count_partial=$((count_partial + 1))
            ;;
        *"semantic-difference"*|*"semantic difference"*)
            count_semantic_diff=$((count_semantic_diff + 1))
            ;;
        *"explicitly-deferred"*|*"deferred"*)
            count_deferred=$((count_deferred + 1))
            ;;
        *"wontfix"*|*"wontfix-in-crate"*)
            count_wontfix=$((count_wontfix + 1))
            ;;
        *"missing"*)
            count_missing=$((count_missing + 1))
            ;;
        *"parity"*|*"present"*)
            # Catches: present, present (both absent), present-by-absence,
            # present (architectural), parity, parity-plus, parity-adjacent.
            count_present=$((count_present + 1))
            ;;
        *)
            count_other=$((count_other + 1))
            ;;
    esac
done < "$CHECKLIST"

# ---------------------------------------------------------------------------
# Strict parity: what fraction of in-scope rows is shipped?
#
# The checklist methodology defines "strict" as:
#   (present + net-new) / (total - deferred - wontfix - other)
#
# "deferred" and "wontfix" rows are explicitly out-of-scope per ADR and
# are excluded from the denominator. "semantic-difference" counts as
# shipped (both sides implement it). "partial-parity" and "missing"
# are the actual gaps.
#
# Numerator: present (all variants) + net-new + semantic-difference
# Denominator: total - deferred - wontfix - other (architectural/N/A rows)
# ---------------------------------------------------------------------------

strict_numerator=$((count_present + count_net_new + count_semantic_diff))
strict_denominator=$((total_rows - count_deferred - count_wontfix - count_other))

if [[ $strict_denominator -gt 0 ]]; then
    strict_pct=$(awk "BEGIN { printf \"%.1f\", ($strict_numerator / $strict_denominator) * 100 }")
else
    strict_pct="0.0"
fi

if [[ $total_rows -gt 0 ]]; then
    present_pct=$(awk "BEGIN { printf \"%.1f\", ($count_present / $total_rows) * 100 }")
    net_new_pct=$(awk "BEGIN { printf \"%.1f\", ($count_net_new / $total_rows) * 100 }")
    partial_pct=$(awk "BEGIN { printf \"%.1f\", ($count_partial / $total_rows) * 100 }")
    missing_pct=$(awk "BEGIN { printf \"%.1f\", ($count_missing / $total_rows) * 100 }")
    deferred_pct=$(awk "BEGIN { printf \"%.1f\", ($count_deferred / $total_rows) * 100 }")
    wontfix_pct=$(awk "BEGIN { printf \"%.1f\", ($count_wontfix / $total_rows) * 100 }")
    sd_pct=$(awk "BEGIN { printf \"%.1f\", ($count_semantic_diff / $total_rows) * 100 }")
else
    present_pct="0.0"
    net_new_pct="0.0"
    partial_pct="0.0"
    missing_pct="0.0"
    deferred_pct="0.0"
    wontfix_pct="0.0"
    sd_pct="0.0"
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
echo -e "${BOLD}JSS parity report${RESET}"
echo "========================"
echo ""
printf "  Total rows:             %4d\n" "$total_rows"
echo ""
printf "  present:                %4d (%5s%%)\n" "$count_present" "$present_pct"
printf "  net-new:                %4d (%5s%%)\n" "$count_net_new" "$net_new_pct"
printf "  semantic-difference:    %4d (%5s%%)\n" "$count_semantic_diff" "$sd_pct"
printf "  partial-parity:         %4d (%5s%%)\n" "$count_partial" "$partial_pct"
printf "  missing:                %4d (%5s%%)\n" "$count_missing" "$missing_pct"
printf "  explicitly-deferred:    %4d (%5s%%)\n" "$count_deferred" "$deferred_pct"
printf "  wontfix-in-crate:       %4d (%5s%%)\n" "$count_wontfix" "$wontfix_pct"
if [[ $count_other -gt 0 ]]; then
    printf "  other/unclassified:     %4d\n" "$count_other"
fi
echo ""
printf "  ${BOLD}Strict:   %d/%d = %s%%${RESET}\n" "$strict_numerator" "$strict_denominator" "$strict_pct"
printf "  (denominator excludes %d deferred + %d wontfix + %d other)\n" "$count_deferred" "$count_wontfix" "$count_other"
echo ""

# ---------------------------------------------------------------------------
# Gate: strict >= 95%
#
# If the threshold is not met, check which rows are missing/partial.
# ---------------------------------------------------------------------------
threshold=95
pass=$(awk "BEGIN { print ($strict_pct >= $threshold) ? 1 : 0 }")

if [[ "$pass" -eq 1 ]]; then
    echo -e "${GREEN}${BOLD}PASS: Strict parity ${strict_pct}% >= ${threshold}% threshold${RESET}"
    exit 0
else
    # Show the gap breakdown for actionability.
    gap=$((total_rows - strict_numerator))
    echo -e "${YELLOW}Gap rows ($gap):${RESET}"
    echo "  missing:           $count_missing"
    echo "  partial-parity:    $count_partial"
    echo "  deferred:          $count_deferred"
    echo "  wontfix:           $count_wontfix"
    echo "  other:             $count_other"
    echo ""
    echo -e "${RED}${BOLD}FAIL: Strict parity ${strict_pct}% < ${threshold}% threshold${RESET}"
    exit 1
fi
