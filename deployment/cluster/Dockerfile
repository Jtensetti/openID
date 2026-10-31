FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS node
FROM python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
LABEL org.opencontainers.image.source="https://github.com/Jtensetti/openID"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/LICENSE /usr/share/doc/nodejs/LICENSE
WORKDIR /app/verification
COPY verification/cluster-requirements.lock verification/runtime-requirements.lock verification/rp-requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r cluster-requirements.lock -r runtime-requirements.lock -r rp-requirements.lock
COPY verification/cluster_bridge.py verification/federation.py verification/cluster_serve.py verification/cluster_operator.py verification/postgres.py verification/transit.py verification/maintenance.py verification/monitor.py verification/runtime.py verification/biometric_worker.py verification/serve.py verification/native.py verification/wallet.py verification/identity.py verification/crypto_runtime.py verification/ipc_support.py ./
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
