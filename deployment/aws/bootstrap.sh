#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y python3.12-venv ca-certificates curl xz-utils
install -d -m 700 /opt/openid-tools /var/tmp/openid-aws
curl --fail --silent --show-error --location --max-time 120 \
  https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.xz -o /opt/openid-tools/node.tar.xz
printf '%s  %s\n' 14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647 /opt/openid-tools/node.tar.xz | sha256sum --check --strict
tar -xJf /opt/openid-tools/node.tar.xz -C /opt/openid-tools
export PATH="/opt/openid-tools/node-v24.19.0-linux-x64/bin:$PATH"
curl --fail --silent --show-error --location --max-time 120 \
  https://github.com/openbao/openbao/releases/download/v2.7.1/openbao_2.7.1_linux_amd64.tar.gz -o /opt/openid-tools/bao.tar.gz
printf '%s  %s\n' 0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243 /opt/openid-tools/bao.tar.gz | sha256sum --check --strict
tar -xzf /opt/openid-tools/bao.tar.gz -C /opt/openid-tools
curl --fail --silent --show-error --max-time 60 \
  https://truststore.pki.rds.amazonaws.com/eu-north-1/eu-north-1-bundle.pem -o /opt/openid-tools/rds-ca.pem
printf '%s  %s\n' 8d8dc42958c7b9351846609d552b4b38f3b19c92c9d4816b2f814fd148fe18be /opt/openid-tools/rds-ca.pem | sha256sum --check --strict
python3.12 -m venv verification/.venv
verification/.venv/bin/pip -q install --require-hashes --only-binary=:all: \
  -r verification/cluster-requirements.lock -r verification/runtime-requirements.lock \
  -r verification/rp-requirements.lock -r deployment/aws/requirements.lock
sed -n '/^numpy==/p; /^opencv-python-headless==/p' verification/requirements.lock > /var/tmp/openid-aws/image-requirements.lock
verification/.venv/bin/pip -q install --require-hashes --only-binary=:all: -r /var/tmp/openid-aws/image-requirements.lock
exec verification/.venv/bin/python deployment/aws/run_tests.py --host "$1" --secret "$2" --ca /opt/openid-tools/rds-ca.pem
