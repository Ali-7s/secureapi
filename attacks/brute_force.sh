#!/usr/bin/env bash
set -euo pipefail

HOST=http://localhost:8080
EMAIL="atk_$(date +%s)@x.test"

for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "$HOST/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"wrong-$i\"}"
done
echo done, check alerts in ~10s