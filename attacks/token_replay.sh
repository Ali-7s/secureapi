#!/usr/bin/env bash
set -euo pipefail

HOST=http://localhost:8080
JAR=$(mktemp)
STAMP=$(date +%s)
EMAIL="replay_$STAMP@x.test"

# register + login
curl -s -o /dev/null -X POST "$HOST/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","username":"rpl%s","displayName":"U","password":"Password12345"}' "$EMAIL" "$STAMP")"
curl -s -o /dev/null -c "$JAR" -X POST "$HOST/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","password":"Password12345"}' "$EMAIL")"

# capture the original refresh token, then rotate once so it becomes stale (revoked)
STALE=$(grep refresh_token "$JAR" | awk '{print $7}')
curl -s -o /dev/null -b "$JAR" -c "$JAR" -X GET "$HOST/api/auth/refresh"

# replay the stale refresh token 12 times
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X GET "$HOST/api/auth/refresh" \
    --cookie "refresh_token=$STALE"
done

rm -f "$JAR"
echo "done. a TOKEN_REPLAY alert should appear within ~10s."
