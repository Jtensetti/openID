#!/usr/bin/env bash
set -euo pipefail
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$RUNNER_TEMP/postgres.key" -out "$RUNNER_TEMP/postgres.crt" 2>/dev/null
docker cp "$RUNNER_TEMP/postgres.key" "$POSTGRES_CONTAINER:/tmp/postgres.key"
docker cp "$RUNNER_TEMP/postgres.crt" "$POSTGRES_CONTAINER:/tmp/postgres.crt"
docker exec --user root "$POSTGRES_CONTAINER" chown postgres:postgres /tmp/postgres.key /tmp/postgres.crt
docker exec --user root "$POSTGRES_CONTAINER" chmod 600 /tmp/postgres.key
docker exec "$POSTGRES_CONTAINER" psql -U postgres -d openid_test -v ON_ERROR_STOP=1 \
  -c "ALTER SYSTEM SET ssl_cert_file='/tmp/postgres.crt'" \
  -c "ALTER SYSTEM SET ssl_key_file='/tmp/postgres.key'" \
  -c "ALTER SYSTEM SET ssl='on'" -c 'SELECT pg_reload_conf()'
