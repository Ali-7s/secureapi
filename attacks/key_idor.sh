#!/usr/bin/env bash
set -euo pipefail

HOST=http://localhost:8080
JAR=$(mktemp)
STAMP=$(date +%s)
EMAIL="idor_$STAMP@x.test"

# register + login the attacker, keeping the session cookies
curl -s -o /dev/null -X POST "$HOST/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","username":"idor%s","displayName":"Atk","password":"Password12345"}' "$EMAIL" "$STAMP")"
curl -s -o /dev/null -c "$JAR" -X POST "$HOST/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","password":"Password12345"}' "$EMAIL")"

# try to delete a key the attacker does not own, 12 times
for i in $(seq 1 12); do
  CSRF=$(grep XSRF-TOKEN "$JAR" | awk '{print $7}')   # re-read: the token rotates each request
  curl -s -o /dev/null -w "%{http_code}\n" -b "$JAR" -c "$JAR" \
    -X DELETE "$HOST/api/keys/999999" \
    -H "X-XSRF-TOKEN: $CSRF"
done

rm -f "$JAR"
echo "done. a KEY_IDOR alert should appear within ~10s."
