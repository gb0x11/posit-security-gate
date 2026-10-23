#!/usr/bin/env bash
# Posit security gate - scan engine.
#
# Runs the security checks that must pass before code may reach a branch that
# Posit Connect deploys from. Used by the GitHub required workflow (via
# action.yml) and runnable locally for testing.
#
#   Secrets : Wiz CLI when WIZ_CLIENT_ID/WIZ_CLIENT_SECRET are set, else gitleaks
#   SCA     : Wiz CLI when Wiz credentials are set, else osv-scanner
#   SAST    : Veracode Pipeline Scan when VERACODE_API_ID/VERACODE_API_KEY are set
#             (Python/JS only; Veracode Pipeline Scan does not list R)
#   Deploy  : manifest.json present (Connect cannot deploy Git-backed content without it)
#
# Usage: scan.sh [dir]        exit 0 = pass, 1 = gate failed, 2 = usage/tool error
set -uo pipefail

SCAN_DIR="${1:-${SCAN_DIR:-.}}"
REPORT_DIR="${REPORT_DIR:-$PWD/security-reports}"
TOOLS_DIR="${TOOLS_DIR:-$HOME/.cache/posit-gate/bin}"
REQUIRE_MANIFEST="${REQUIRE_MANIFEST:-true}"
VERACODE_FAIL_ON="${VERACODE_FAIL_ON:-Very High, High}"
OSV_MIN_CVSS="${OSV_MIN_CVSS:-7.0}"   # fallback SCA fails only on High/Critical (CVSS >= this)
OSV_FAIL_UNSCORED="${OSV_FAIL_UNSCORED:-false}"  # R (RSEC) advisories carry no CVSS; set true to block on them
WIZ_SCAN_CMD="${WIZ_SCAN_CMD:-wizcli dir scan --path}"   # override if your wizcli version uses "scan dir"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"
GITLEAKS_CONFIG="${GITLEAKS_CONFIG:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gitleaks.toml}"
OSV_VERSION="${OSV_VERSION:-1.9.2}"

[ -d "$SCAN_DIR" ] || { echo "scan dir not found: $SCAN_DIR" >&2; exit 2; }
SCAN_DIR="$(cd "$SCAN_DIR" && pwd)"
mkdir -p "$REPORT_DIR" "$TOOLS_DIR"
export PATH="$TOOLS_DIR:$PATH"

SUMMARY="$REPORT_DIR/summary.md"
FAILED=0
: > "$SUMMARY"

log()    { printf '\n==> %s\n' "$*"; }
record() { # record <check> <PASS|FAIL|SKIP|WARN> <detail>
  printf '| %s | %s | %s |\n' "$1" "$2" "$3" >> "$SUMMARY.rows"
  [ "$2" = "FAIL" ] && FAILED=1
  return 0
}
: > "$SUMMARY.rows"

os_arch() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in x86_64|amd64) arch=amd64; arch_gl=x64;; arm64|aarch64) arch=arm64; arch_gl=arm64;; *) arch=amd64; arch_gl=x64;; esac
  echo "$os $arch $arch_gl"
}

ensure_gitleaks() {
  command -v gitleaks >/dev/null && return 0
  read -r os arch arch_gl <<<"$(os_arch)"
  log "installing gitleaks $GITLEAKS_VERSION"
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${os}_${arch_gl}.tar.gz" \
    | tar -xz -C "$tmp" gitleaks && mv "$tmp/gitleaks" "$TOOLS_DIR/" && chmod +x "$TOOLS_DIR/gitleaks"
}

ensure_osv() {
  command -v osv-scanner >/dev/null && return 0
  read -r os arch _ <<<"$(os_arch)"
  log "installing osv-scanner $OSV_VERSION"
  curl -fsSL -o "$TOOLS_DIR/osv-scanner" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${os}_${arch}" \
    && chmod +x "$TOOLS_DIR/osv-scanner"
}

ensure_wizcli() {
  command -v wizcli >/dev/null && return 0
  read -r os arch _ <<<"$(os_arch)"
  log "installing wizcli"
  curl -fsSL -o "$TOOLS_DIR/wizcli" "https://downloads.wiz.io/wizcli/latest/wizcli-${os}-${arch}" \
    && chmod +x "$TOOLS_DIR/wizcli"
}

# ---------------------------------------------------------------- detection
has_files() { find "$SCAN_DIR" -path "$SCAN_DIR/.git" -prune -o -type f \( "$@" \) -print -quit 2>/dev/null | grep -q .; }
LANG_PY=false; LANG_R=false; LANG_JS=false
has_files -name '*.py' -o -name 'requirements.txt' -o -name 'pyproject.toml' && LANG_PY=true
has_files -name '*.R' -o -name '*.r' -o -name '*.Rmd' -o -name 'renv.lock' -o -name 'DESCRIPTION' && LANG_R=true
has_files -name '*.js' -o -name '*.ts' -o -name 'package.json' && LANG_JS=true
log "scanning $SCAN_DIR  (python=$LANG_PY r=$LANG_R js=$LANG_JS)"

USE_WIZ=false
[ -n "${WIZ_CLIENT_ID:-}" ] && [ -n "${WIZ_CLIENT_SECRET:-}" ] && USE_WIZ=true

# ---------------------------------------------------------------- deployability
if [ -f "$SCAN_DIR/manifest.json" ]; then
  record "Connect manifest" PASS "manifest.json present"
elif [ "$REQUIRE_MANIFEST" = "true" ]; then
  record "Connect manifest" FAIL "manifest.json missing - Connect cannot deploy this repo (rsconnect write-manifest ...)"
else
  record "Connect manifest" WARN "manifest.json missing"
fi

# ---------------------------------------------------------------- Wiz (secrets + SCA)
if $USE_WIZ; then
  log "Wiz CLI scan (secrets + SCA)"
  if ensure_wizcli && wizcli auth --id "$WIZ_CLIENT_ID" --secret "$WIZ_CLIENT_SECRET" >/dev/null; then
    # shellcheck disable=SC2086
    $WIZ_SCAN_CMD "$SCAN_DIR" ${WIZ_POLICY:+--policy "$WIZ_POLICY"} > "$REPORT_DIR/wiz.txt" 2>&1
    rc=$?
    tail -40 "$REPORT_DIR/wiz.txt"
    if [ $rc -eq 0 ]; then record "Secrets + SCA (Wiz)" PASS "policy passed"
    else record "Secrets + SCA (Wiz)" FAIL "policy failed (exit $rc) - see wiz.txt"; fi
  else
    record "Secrets + SCA (Wiz)" FAIL "wizcli install/auth failed"
  fi
else
  # ---------------------------------------------------------------- gitleaks
  log "Secret scan (gitleaks - Wiz credentials not set)"
  if ensure_gitleaks; then
    gitleaks dir "$SCAN_DIR" --config "$GITLEAKS_CONFIG" --redact --no-banner --exit-code 3 \
      --report-format json --report-path "$REPORT_DIR/gitleaks.json" 2>&1 | tail -5
    rc=${PIPESTATUS[0]}
    n=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$REPORT_DIR/gitleaks.json" 2>/dev/null || echo "?")
    case $rc in
      0) record "Secrets (gitleaks)" PASS "no secrets found" ;;
      3) record "Secrets (gitleaks)" FAIL "$n secret(s) found - see gitleaks.json" ;;
      *) record "Secrets (gitleaks)" FAIL "gitleaks error (exit $rc)" ;;
    esac
  else
    record "Secrets (gitleaks)" FAIL "gitleaks install failed"
  fi

  # ---------------------------------------------------------------- osv-scanner
  log "Dependency scan (osv-scanner - Wiz credentials not set)"
  if ensure_osv; then
    # R content published with rsconnect often has no renv.lock - only manifest.json
    # "packages". Derive a renv.lock from it so osv-scanner can check CRAN advisories.
    osv_targets=("$SCAN_DIR")
    if [ -f "$SCAN_DIR/manifest.json" ] && [ ! -f "$SCAN_DIR/renv.lock" ]; then
      rdir="$REPORT_DIR/r-from-manifest"
      if python3 - "$SCAN_DIR/manifest.json" "$rdir" <<'PY'
import json, os, sys
m = json.load(open(sys.argv[1]))
pkgs = {}
for name, p in (m.get("packages") or {}).items():
    desc = p.get("description") or {}
    if desc.get("Version"):
        pkgs[name] = {"Package": name, "Version": desc["Version"],
                      "Source": "Repository", "Repository": p.get("Source") or "CRAN"}
if not pkgs:
    sys.exit(1)
os.makedirs(sys.argv[2], exist_ok=True)
json.dump({"R": {"Version": (m.get("platform") or "")}, "Packages": pkgs},
          open(os.path.join(sys.argv[2], "renv.lock"), "w"), indent=1)
print(f"derived renv.lock with {len(pkgs)} R packages from manifest.json")
PY
      then osv_targets+=("$rdir"); fi
    fi
    osv-scanner --recursive --format json --output "$REPORT_DIR/osv.json" "${osv_targets[@]}" >/dev/null 2>"$REPORT_DIR/osv.log"
    rc=$?
    # osv "groups" merge aliases of one vulnerability; max_severity is its CVSS base score.
    read -r total high unscored <<<"$(python3 - "$REPORT_DIR/osv.json" "$OSV_MIN_CVSS" <<'PY' 2>/dev/null || echo "? ? ?"
import json, sys
d, limit = json.load(open(sys.argv[1])), float(sys.argv[2])
total = high = unscored = 0
for r in d.get("results", []):
    for p in r.get("packages", []):
        for grp in p.get("groups", []):
            total += 1
            try:
                high += float(grp.get("max_severity") or "") >= limit
            except ValueError:
                unscored += 1
print(total, high, unscored)
PY
)"
    case $rc in
      0)   record "Dependencies (osv-scanner)" PASS "no known vulnerabilities" ;;
      1)   if [ "$high" = "0" ] && ! { [ "$OSV_FAIL_UNSCORED" = "true" ] && [ "$unscored" != "0" ]; }; then
             record "Dependencies (osv-scanner)" WARN "$total known vulnerabilit(ies), none CVSS>=$OSV_MIN_CVSS ($unscored unscored) - see osv.json"
           else
             record "Dependencies (osv-scanner)" FAIL "$high of $total vulnerabilit(ies) CVSS>=$OSV_MIN_CVSS, $unscored unscored (OSV_FAIL_UNSCORED=$OSV_FAIL_UNSCORED) - see osv.json"
           fi ;;
      128) record "Dependencies (osv-scanner)" WARN "no lockfile/requirements found to scan" ;;
      *)   record "Dependencies (osv-scanner)" FAIL "osv-scanner error (exit $rc) - see osv.log" ;;
    esac
  else
    record "Dependencies (osv-scanner)" FAIL "osv-scanner install failed"
  fi
fi

# ---------------------------------------------------------------- Veracode SAST
if [ -n "${VERACODE_API_ID:-}" ] && [ -n "${VERACODE_API_KEY:-}" ]; then
  if $LANG_PY || $LANG_JS; then
    log "SAST (Veracode Pipeline Scan)"
    work="$(mktemp -d)"
    ( cd "$SCAN_DIR" && zip -qr "$work/app.zip" . -x '.git/*' 'renv/library/*' '.venv/*' 'node_modules/*' )
    curl -fsSL -o "$work/ps.zip" https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip \
      && unzip -qo "$work/ps.zip" -d "$work"
    java -jar "$work/pipeline-scan.jar" \
      --veracode_api_id "$VERACODE_API_ID" --veracode_api_key "$VERACODE_API_KEY" \
      --file "$work/app.zip" --fail_on_severity "$VERACODE_FAIL_ON" \
      --json_output_file "$REPORT_DIR/veracode.json" > "$REPORT_DIR/veracode.txt" 2>&1
    rc=$?
    tail -25 "$REPORT_DIR/veracode.txt"
    if [ $rc -eq 0 ]; then record "SAST (Veracode)" PASS "no findings at: $VERACODE_FAIL_ON"
    else record "SAST (Veracode)" FAIL "findings at $VERACODE_FAIL_ON or scan error (exit $rc)"; fi
  else
    record "SAST (Veracode)" WARN "no Python/JS code; Veracode Pipeline Scan does not cover R"
  fi
else
  record "SAST (Veracode)" SKIP "VERACODE_API_ID/KEY not set"
fi

# ---------------------------------------------------------------- summary
{
  echo "## Posit security gate"
  echo
  echo "Scanned: \`$(basename "$SCAN_DIR")\` - python=$LANG_PY r=$LANG_R js=$LANG_JS"
  echo
  echo "| Check | Result | Detail |"
  echo "|---|---|---|"
  cat "$SUMMARY.rows"
  echo
  if [ $FAILED -eq 0 ]; then echo "**Gate: PASSED**"; else echo "**Gate: FAILED** - fix the findings above before merging."; fi
} > "$SUMMARY"
rm -f "$SUMMARY.rows"

cat "$SUMMARY"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$SUMMARY" >> "$GITHUB_STEP_SUMMARY"
exit $FAILED
