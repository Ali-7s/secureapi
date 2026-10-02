#!/usr/bin/env bash
set -euo pipefail

HOST=http://localhost:8080
JAR=$(mktemp)
STAMP=$(date +%s)
EMAIL="scope_$STAMP@x.test"

# register + login
curl -s -o /dev/null -X POST "$HOST/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","username":"scope%s","displayName":"U","password":"Password12345"}' "$EMAIL" "$STAMP")"
curl -s -o /dev/null -c "$JAR" -X POST "$HOST/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","password":"Password12345"}' "$EMAIL")"

# create a read-only key (this write needs the CSRF token), capture the plaintext
CSRF=$(grep XSRF-TOKEN "$JAR" | awk '{print $7}')
RESP=$(curl -s -b "$JAR" -c "$JAR" -X POST "$HOST/api/keys" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{"label":"read only","scopes":"ALERTS_READ"}')
KEY=$(echo "$RESP" | grep -o '"plaintextKey":"[^"]*"' | cut -d'"' -f4)

# use the read-only key to acknowledge, which requires ALERTS_WRITE, 12 times.
# the scope check runs before the alert is looked up, so the alert id need not exist.
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "$HOST/api/alerts/1/acknowledge" \
    -H "X-API-Key: $KEY"
done

rm -f "$JAR"
echo "done. a WRONG_SCOPE_KEY alert should appear within ~10s."
