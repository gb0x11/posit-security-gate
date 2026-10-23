#!/usr/bin/env bash
# Self-tests for the gate. Run from anywhere: bash tests/run_tests.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export TOOLS_DIR="${TOOLS_DIR:-$HOME/.cache/posit-gate/bin}"
fails=0

expect() { # expect <fixture> <exit> [ENV=VAL...]
  local fx=$1 want=$2; shift 2
  env "$@" REPORT_DIR="$TMP/$fx-$want" bash "$ROOT/scan.sh" "$ROOT/tests/fixtures/$fx" >"$TMP/log" 2>&1
  local got=$?
  if [ "$got" = "$want" ]; then echo "PASS  $fx -> exit $got $*"
  else echo "FAIL  $fx -> exit $got, expected $want $*"; sed -n '/^| Check/,$p' "$TMP/log"; fails=$((fails+1)); fi
}

expect good-python-app 0
expect bad-python-app 1
expect bad-r-app 1
expect good-python-app 0 OSV_FAIL_UNSCORED=true

# R secret rule: lines 2-5 flagged, 6-9 not.
gitleaks dir "$ROOT/tests/secret-rules" --config "$ROOT/gitleaks.toml" --no-banner --redact \
  --report-format json --report-path "$TMP/rules.json" >/dev/null 2>&1
lines=$(python3 -c 'import json,sys;print(" ".join(str(l["StartLine"]) for l in sorted(json.load(open(sys.argv[1])),key=lambda l:l["StartLine"])))' "$TMP/rules.json")
if [ "$lines" = "2 3 4 5" ]; then echo "PASS  R secret rule flags lines: $lines"
else echo "FAIL  R secret rule flagged lines: '$lines', expected '2 3 4 5'"; fails=$((fails+1)); fi

echo; [ $fails -eq 0 ] && echo "all gate tests passed" || echo "$fails gate test(s) failed"
exit $fails
