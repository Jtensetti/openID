#!/usr/bin/env bash
set -euo pipefail
umask 077
PORT="$(printenv PORT || printf 10000)"
if [[ ! "$PORT" =~ ^[0-9]{4,5}$ ]] || (( PORT < 1024 || PORT > 65535 )); then
  echo "Invalid Render PORT" >&2
  exit 2
fi
test -r /srv/tjipp-sandbox/keys/federation.p12
test -r /app/settings.json
mkdir -p /tmp/tjipp-sandbox
chmod 0700 /tmp/tjipp-sandbox
sed "s/@PORT@/$PORT/g" /app/nginx.render.conf > /tmp/tjipp-sandbox-nginx.conf
nginx -t -c /tmp/tjipp-sandbox-nginx.conf

# Keys are synthetic test-only credentials generated during this image's build.
# They survive Render Free spin-down and restart of this exact image.
java -Xms48m -Xmx280m -XX:MaxMetaspaceSize=130m -XX:+ExitOnOutOfMemoryError \
  -jar /app/isolated-eid-lab.jar sandbox-idp \
  /srv/tjipp-sandbox/keys /app/settings.json &
IDP_PID=$!
NGINX_PID=""
cleanup() {
  if [[ -n "$NGINX_PID" ]]; then kill "$NGINX_PID" 2>/dev/null || true; fi
  kill "$IDP_PID" 2>/dev/null || true
}
trap cleanup EXIT TERM INT

for i in $(seq 1 90); do
  if ! kill -0 "$IDP_PID" 2>/dev/null; then
    echo "Sandbox IdP failed before readiness" >&2
    wait "$IDP_PID" || true
    exit 1
  fi
  # The IdP deliberately rejects every Host except the configured public origin.
  # Verify loopback TLS as localhost while using the same Host as nginx.
  if curl --silent --show-error --fail --max-time 2 --noproxy '*' \
      --header 'Host: tjipp-sweden-connect-sandbox.onrender.com' \
      --cacert /srv/tjipp-sandbox/keys/tls.crt \
      https://localhost:9443/saml2/metadata >/dev/null 2>/dev/null; then
    break
  fi
  if (( i == 90 )); then
    echo "Sandbox IdP readiness failed closed" >&2
    exit 1
  fi
  sleep 2
done

nginx -c /tmp/tjipp-sandbox-nginx.conf -g "daemon off;" &
NGINX_PID=$!
echo "Synthetic-only Render ingress started on $PORT; no LoA3, no real IDs."
wait -n "$IDP_PID" "$NGINX_PID" || true
echo "Sandbox runtime component stopped; terminating both" >&2
exit 1
