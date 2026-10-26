FROM python:3.12.15-trixie@sha256:0d0db5b17f11b1b7d1aafa74ceadaa64ba0944b267ff6fc22008a197acd6b9ad AS python-build
ADD --checksum=sha256:b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz /tmp/python-source.tar.xz
ADD --checksum=sha256:6c268edc3c8b9b12a875b3d3ed2495983b8a4a94c070927863b942722a9a216c https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz.spdx.json /tmp/python-source.spdx.json
COPY deployment/build/build_python.sh /build-python.sh
COPY deployment/build/patch_python_test.py /patch-python-test.py
COPY deployment/build/python-runtime.lock.json /tmp/python-runtime.lock.json
COPY deployment/build/licenses/docker-library-python-LICENSE.txt /tmp/docker-library-python-LICENSE
RUN --network=none bash /build-python.sh

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS node
FROM python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
# Replace the entire previous Python installation, including its standard library.
RUN rm -rf /usr/local
COPY --from=python-build /stage/usr/local /usr/local
COPY --from=python-build /stage/usr/share/doc/openid-python /usr/share/doc/openid-python
ENV PYTHON_VERSION=3.12.16 PYTHON_SHA256=b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c
RUN ldconfig && python -c 'import sys,ssl,sqlite3,pyexpat,bz2,lzma,ctypes,hashlib; assert sys.version_info[:3] == (3,12,16); assert pyexpat.EXPAT_VERSION == "expat_2.9.0"'
ADD --checksum=sha256:fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70 https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl /tmp/pip-26.2.2-py3-none-any.whl
COPY deployment/build/install_build_pip.py /tmp/install_build_pip.py
RUN --network=none python /tmp/install_build_pip.py && rm /tmp/install_build_pip.py /tmp/pip-26.2.2-py3-none-any.whl
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
COPY deployment/build/remove_build_pip.py /tmp/remove_build_pip.py
RUN --network=none python /tmp/remove_build_pip.py && rm /tmp/remove_build_pip.py
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=6s --start-period=30s --retries=3 CMD ["python","probe.py","/srv/openid/runtime.json"]
ENTRYPOINT ["python","cluster_serve.py"]
CMD ["--config","/srv/openid/runtime.json"]
