#!/usr/bin/env bash
# Run this before judging. It checks every requirement and tells you exactly what will not work.
set -u
cd "$(dirname "$0")/.."
ok()   { echo "  [OK]   $*"; }
warn() { echo "  [WARN] $*"; }
fail() { echo "  [FAIL] $*"; FAILED=1; }
FAILED=0

echo "1. Tooling"
python3 --version >/dev/null 2>&1 && ok "python3 found" || fail "python3 not found"
command -v npm >/dev/null 2>&1 && ok "npm found (needed for PR lockfile regeneration)" || warn "npm missing: PR creation will be refused"

echo "2. Live vulnerability intelligence (OSV.dev)"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "${OSV_URL:-https://api.osv.dev/v1/query}" \
  -H 'content-type: application/json' -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.15"}')
if [ "$code" = "200" ]; then ok "OSV.dev reachable (HTTP 200)"; else fail "OSV.dev not reachable (got '$code'). Scans will show UNAVAILABLE."; fi

echo "3. CISA KEV feed (exploit status)"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" "${KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}")
[ "$code" = "200" ] && ok "KEV reachable" || warn "KEV not reachable: exploit status will be shown as unavailable"

echo "4. GitHub integration"
if [ -n "${GITHUB_TOKEN:-}" ]; then
  code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user)
  [ "$code" = "200" ] && ok "GITHUB_TOKEN is valid" || fail "GITHUB_TOKEN rejected by GitHub (HTTP $code)"
else
  warn "GITHUB_TOKEN not set: scanning works, PR creation will be refused"
fi

echo "5. Test suite"
if python3 -m pytest -q backend/tests >/tmp/sg_tests.log 2>&1; then ok "$(tail -1 /tmp/sg_tests.log)"; else fail "tests failing, see /tmp/sg_tests.log"; fi

echo "6. Engine on the sample project"
python3 -m app.cli scan examples/vulnerable-app --out reports/preflight >/tmp/sg_cli.log 2>&1 && ok "CLI scan completed (reports/preflight)" || fail "CLI scan failed, see /tmp/sg_cli.log"
grep -q "Vulnerability data: LIVE" /tmp/sg_cli.log && ok "vulnerability data is LIVE" || warn "vulnerability data is not live; judges will see that banner"

echo
[ "$FAILED" = "0" ] && echo "Preflight passed." || echo "Preflight has failures. Fix them before the demo."
exit $FAILED
