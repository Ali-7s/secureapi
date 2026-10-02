#!/usr/bin/env bash
set -euo pipefail

HOST=http://localhost:8080
JAR=$(mktemp)
STAMP=$(date +%s)
EMAIL="revoked_$STAMP@x.test"

# register + login
curl -s -o /dev/null -X POST "$HOST/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","username":"rvk%s","displayName":"U","password":"Password12345"}' "$EMAIL" "$STAMP")"
curl -s -o /dev/null -c "$JAR" -X POST "$HOST/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","password":"Password12345"}' "$EMAIL")"

# create a key, capture its plaintext and id
CSRF=$(grep XSRF-TOKEN "$JAR" | awk '{print $7}')
RESP=$(curl -s -b "$JAR" -c "$JAR" -X POST "$HOST/api/keys" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{"label":"soon revoked","scopes":"ALERTS_READ"}')
KEY=$(echo "$RESP" | grep -o '"plaintextKey":"[^"]*"' | cut -d'"' -f4)
ID=$(echo "$RESP" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)

# revoke it (CSRF rotated after the create, so re-read the token)
CSRF=$(grep XSRF-TOKEN "$JAR" | awk '{print $7}')
curl -s -o /dev/null -b "$JAR" -c "$JAR" -X DELETE "$HOST/api/keys/$ID" \
  -H "X-XSRF-TOKEN: $CSRF"

# replay the revoked key against the alert feed, 12 times
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X GET "$HOST/api/alerts" \
    -H "X-API-Key: $KEY"
done

rm -f "$JAR"
echo "done. a REVOKED_KEY_REPLAY alert should appear within ~10s."
