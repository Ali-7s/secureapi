#!/usr/bin/env bash
set -euo pipefail

HOST=http://localhost:8080
STAMP=$(date +%s)

# One source, many different accounts, each tried once with a wrong password.
# 10+ distinct principals from one source trips PasswordSprayingRule.
for i in $(seq 1 12); do
  BODY=$(printf '{"email":"spray_%s_%s@x.test","password":"wrong"}' "$STAMP" "$i")
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "$HOST/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "$BODY"
done

echo "done. a PASSWORD_SPRAY alert should appear within ~10s."
