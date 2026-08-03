#!/usr/bin/env bash
# Prod smoke test, through Cloudflare Access.
#
# Prod sits behind Access, so a plain curl gets a 302 to the login page and every
# check below would "pass" against an HTML redirect. This uses an Access *service
# token* (CF-Access-Client-Id / CF-Access-Client-Secret) to authenticate as a
# machine, which is the supported way to reach a protected hostname from CLI.
#
#   Setup: Zero Trust > Access > Service Auth > create a service token, then put
#   CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET in .env (gitignored).
#
#   IMPORTANT: the token only works if the Access application protecting the
#   hostname has a *Service Auth* policy that admits it. A valid token with no
#   matching policy is still refused.
#
# Usage:  ./scripts/prod-smoke.sh [hostname]
#
# Exit codes: 0 all checks passed · 1 a check failed · 2 setup problem.
set -uo pipefail

HOST="${1:-cf-ai-waf-demo.nttlab.org}"
BASE="https://${HOST}"
ENV_FILE="$(dirname "$0")/../.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "✗ no .env at $ENV_FILE" >&2
  exit 2
fi

# Read only the two keys we need. Never echoed — only their presence is reported.
CF_ACCESS_CLIENT_ID=$(grep -E '^CF_ACCESS_CLIENT_ID=' "$ENV_FILE" | cut -d= -f2- | tr -d '"'\''' | tr -d '\r')
CF_ACCESS_CLIENT_SECRET=$(grep -E '^CF_ACCESS_CLIENT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '"'\''' | tr -d '\r')

if [[ -z "$CF_ACCESS_CLIENT_ID" || -z "$CF_ACCESS_CLIENT_SECRET" ]]; then
  echo "✗ CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET are empty in .env" >&2
  exit 2
fi

AUTH=(-H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}")
JSON=(-H 'content-type: application/json')
FAIL=0

hr() { printf '%s\n' "────────────────────────────────────────────────────────"; }

# Prints PASS/FAIL and the first bytes of the body, so a redirect-to-login or an
# upstream auth error is visible rather than being swallowed by a 200.
check() {
  local name="$1" expect="$2" file="$3" code="$4"
  if [[ "$code" == "$expect" ]]; then
    printf '  ✓ %-34s http=%s\n' "$name" "$code"
  else
    printf '  ✗ %-34s http=%s (expected %s)\n' "$name" "$code" "$expect"
    FAIL=1
  fi
  head -c 220 "$file" 2>/dev/null | tr -d '\n' | sed 's/^/      /'
  echo
}

hr
echo "Prod smoke — ${BASE}"
hr

# 1. Access itself. A 302 here means the service token was not accepted (usually
#    no Service Auth policy admits it), and nothing below can be trusted.
echo "[1] Access + static app"
CODE=$(curl -s -o /tmp/smoke1.txt -w '%{http_code}' "${AUTH[@]}" "$BASE/api/models" --max-time 25)
check "GET /api/models" 200 /tmp/smoke1.txt "$CODE"
if [[ "$CODE" == "302" ]]; then
  echo
  echo "  → Access refused the service token. Check that the Access app for this"
  echo "    hostname has a Service Auth policy including this token."
  exit 1
fi

# 2. Direct Workers AI route — the default path, no CF_AIG_TOKEN involved.
echo
echo "[2] Direct Workers AI route"
CODE=$(curl -s -o /tmp/smoke2.txt -w '%{http_code}' "${AUTH[@]}" "${JSON[@]}" \
  -X POST "$BASE/api/chat" \
  -d '{"prompt":"Reply with the single word OK.","stream":false,"excludeFromLog":true}' --max-time 60)
check "POST /api/chat (direct)" 200 /tmp/smoke2.txt "$CODE"

# 3. AI Gateway route — this is the one that needs CF_AIG_TOKEN. A mis-scoped
#    token surfaces as {"code":10000,"message":"Authentication error"}.
echo
echo "[3] AI Gateway route (exercises CF_AIG_TOKEN)"
CODE=$(curl -s -o /tmp/smoke3.txt -w '%{http_code}' "${AUTH[@]}" "${JSON[@]}" \
  -X POST "$BASE/api/chat" \
  -d '{"prompt":"Reply with the single word OK.","gateway":true,"stream":false,"excludeFromLog":true}' --max-time 60)
check "POST /api/chat (gateway)" 200 /tmp/smoke3.txt "$CODE"
if grep -q '"code":10000' /tmp/smoke3.txt 2>/dev/null; then
  echo "  → CF_AIG_TOKEN is mis-scoped in prod. Needs AI Gateway Read + Edit and"
  echo "    Workers AI Read on a normal API token (not the Authenticated Gateway"
  echo "    'Run' token). Roll back with: npx wrangler rollback"
  FAIL=1
fi

# 4. A prompt the WAF should stop. 403 is the PASS here — a 200 means the edge
#    let PII through, which is the demo's whole claim failing.
echo
echo "[4] Edge WAF still blocks PII (403 expected)"
CODE=$(curl -s -o /tmp/smoke4.txt -w '%{http_code}' "${AUTH[@]}" "${JSON[@]}" \
  -X POST "$BASE/api/chat" \
  -d '{"prompt":"my credit card is 4111 1111 1111 1111","stream":false,"excludeFromLog":true}' --max-time 60)
check "POST /api/chat (PII → blocked)" 403 /tmp/smoke4.txt "$CODE"

# 5. Read-only endpoints that back the analytics page.
echo
echo "[5] Read-only endpoints"
for path in "/api/neurons" "/api/analytics?hours=1" "/api/zone-rules" "/api/prompt-log?limit=1"; do
  CODE=$(curl -s -o /tmp/smoke5.txt -w '%{http_code}' "${AUTH[@]}" "$BASE$path" --max-time 30)
  check "GET $path" 200 /tmp/smoke5.txt "$CODE"
done

hr
if [[ "$FAIL" == "0" ]]; then
  echo "ALL CHECKS PASSED"
else
  echo "FAILURES ABOVE — consider: npx wrangler rollback"
fi
hr
exit "$FAIL"
