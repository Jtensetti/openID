#!/usr/bin/env bash
# Disposable sandbox material only. Do not use these exportable keys in production.
set -euo pipefail
umask 077

if [[ $# -ne 0 ]]; then
  printf 'Usage: %s (no arguments; writes .local next to this script)\n' "${0##*/}" >&2
  exit 64
fi
command -v openssl >/dev/null || { echo 'OpenSSL is required' >&2; exit 69; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
output="$script_dir/.local"
if [[ -e "$output" || -L "$output" ]]; then
  echo 'Refusing to overwrite existing .local directory or symlink; rotate via a separate reviewed procedure.' >&2
  exit 73
fi
mkdir -m 700 -- "$output"

for role in signing encryption; do
  private="$output/saml-$role.key"
  public="$output/saml-$role.crt"
  if [[ "$role" == signing ]]; then
    usage='digitalSignature'
  else
    usage='keyEncipherment'
  fi

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$private" 2>/dev/null
  chmod 600 "$private"
  openssl req -new -x509 -sha256 -days 730 \
    -key "$private" -out "$public" \
    -subj "/C=SE/O=Tjipp sandbox/CN=Tjipp SANDBOX SAML $role" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext "keyUsage=critical,$usage" \
    -addext 'subjectKeyIdentifier=hash' 2>/dev/null
  chmod 600 "$public"

  # Verify the certificate is self-signed, valid now, and matches the private key.
  openssl verify -CAfile "$public" "$public" >/dev/null
  diff -q <(openssl pkey -in "$private" -pubout 2>/dev/null) \
    <(openssl x509 -in "$public" -pubkey -noout) >/dev/null || {
      echo "Private/public key mismatch: $role" >&2
      exit 1
    }
done
if cmp -s "$output/saml-signing.crt" "$output/saml-encryption.crt"; then
  echo 'Separate signing and encryption certificates are required' >&2
  exit 1
fi
printf '%s\n' 'Created SANDBOX ONLY SAML credentials in a private directory.' \
  'They are NOT connected to the running IdP; do NOT submit them as deployed metadata.'
for role in signing encryption; do
  openssl x509 -in "$output/saml-$role.crt" -fingerprint -sha256 -noout
  printf '%s\n' "  role=$role"
done
