FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS node
FROM python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
COPY deployment/build/patch_debian.py deployment/build/debian-runtime.lock.json /tmp/openid-os-patches/
RUN python /tmp/openid-os-patches/patch_debian.py && rm -rf /tmp/openid-os-patches
LABEL org.opencontainers.image.source="https://github.com/Jtensetti/openID"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/LICENSE /usr/share/doc/nodejs/LICENSE
WORKDIR /app/verification
COPY verification/cluster-requirements.lock verification/runtime-requirements.lock verification/rp-requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r cluster-requirements.lock -r runtime-requirements.lock -r rp-requirements.lock
COPY verification/cluster_bridge.py verification/federation.py verification/cluster_serve.py verification/cluster_operator.py verification/postgres.py verification/transit.py verification/maintenance.py verification/monitor.py verification/runtime.py verification/biometric_worker.py verification/serve.py verification/native.py verification/wallet.py verification/identity.py verification/crypto_runtime.py ./
COPY verification/crypto-worker.mjs verification/device-signature.mjs verification/profile-crypto.mjs ./
COPY verification/licenses /app/licenses
COPY verification/THIRD_PARTY.md /app/licenses/components.md
COPY deployment/cluster/probe.py ./probe.py
COPY verification/cluster_recovery.py verification/audit_archive.py ./
COPY deployment/cluster/schema.sql /app/deployment/cluster/schema.sql
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=6s --start-period=30s --retries=3 CMD ["python","probe.py","/srv/openid/runtime.json"]
ENTRYPOINT ["python","cluster_serve.py"]
CMD ["--config","/srv/openid/runtime.json"]
