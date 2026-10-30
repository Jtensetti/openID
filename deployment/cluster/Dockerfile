# Download exact reviewed artifacts with BuildKit; pip never downloads them.
FROM scratch AS python-wheels
ADD --checksum=sha256:bd249d0b3f7972f7432f0a6b6ff3b3ee2d129f70cd1ff6c09a9dd9e29a2b88e3 https://files.pythonhosted.org/packages/fe/85/7522a52e5e2f42faf1a129113ab63e548c42e103e9af395b7bfe65e403e2/gunicorn-26.2.0-py3-none-any.whl /wheels/gunicorn-26.2.0-py3-none-any.whl
ADD --checksum=sha256:a1db9f7148b06a28606767efaca51fa6f9398c5c0a3810519be69d7000bdb631 https://files.pythonhosted.org/packages/4e/de/748bd7609c71cae5d737f0ba9192f19329f70180ecda8fff3cac02c5abe3/psycopg-3.3.6-py3-none-any.whl /wheels/psycopg-3.3.6-py3-none-any.whl
ADD --checksum=sha256:1679a1cb93fbe5a6d1fd58d82cbddcc6fcb8c61446ba7cae6eb2a7b19bc585de https://files.pythonhosted.org/packages/0a/42/948bb3d2617795093512613fd96ba380e922992c7908fbc073858147d196/psycopg_binary-3.3.6-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl /wheels/psycopg_binary-3.3.6-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl
ADD --checksum=sha256:9b9cd6a4fcec47a410f7e82d408540e7f77b478509e91b44c1a5457a13e5ff37 https://files.pythonhosted.org/packages/5d/b4/452c6607a0f479465cd8a9b0d9956919fcb150050c1f83f9f11e6b8ee8dc/psycopg_pool-3.3.3-py3-none-any.whl /wheels/psycopg_pool-3.3.3-py3-none-any.whl
ADD --checksum=sha256:16e64e0716c14960108e85d853062c9e8bba5ca8252c0b4d0231b9df4060ff4f https://files.pythonhosted.org/packages/dd/b8/d2d6d731733f51684bbf76bf34dab3b70a9148e8f2cef2bb544fccec681a/qrcode-8.2-py3-none-any.whl /wheels/qrcode-8.2-py3-none-any.whl
ADD --checksum=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8 https://files.pythonhosted.org/packages/49/d3/b8441a820a491ddfc024b0b0cf0393375b75ea13866d9c66727e54c2fc80/typing_extensions-4.16.0-py3-none-any.whl /wheels/typing_extensions-4.16.0-py3-none-any.whl

FROM python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS build-tools
ADD --checksum=sha256:2377cd4a2efed58905da580f835fbdf2a6ed4ad0f10ff541827153a42d491cee https://github.com/chainguard-dev/apko/releases/download/v1.4.13/apko_1.4.13_linux_amd64.tar.gz /tmp/apko.tar.gz
COPY deployment/build/build_runtime.py deployment/build/apk_inventory.py deployment/build/wolfi-runtime.yaml deployment/build/wolfi-runtime.lock.json deployment/build/runtime-tools.lock.json /build-runtime/
COPY deployment/build/licenses/Apko-LICENSE.txt /build-runtime/Apko-LICENSE.txt
RUN tar -xzf /tmp/apko.tar.gz -C /tmp --strip-components=1 apko_1.4.13_linux_amd64/apko && python /build-runtime/build_runtime.py

FROM scratch AS python-base
COPY --from=build-tools /runtime/ /
ENV PATH="/usr/local/bin:/usr/bin:/bin" LANG=C.UTF-8
COPY deployment/build/python-runtime.lock.json /usr/share/doc/openid-python/build-lock.json
ADD --checksum=sha256:fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70 https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl /tmp/pip-26.2.2-py3-none-any.whl
COPY deployment/build/install_build_pip.py /tmp/install_build_pip.py
RUN --network=none ["python", "/tmp/install_build_pip.py"]

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS node
FROM python-base
LABEL org.opencontainers.image.source="https://github.com/Jtensetti/openID"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/LICENSE /usr/share/doc/nodejs/LICENSE
WORKDIR /app/verification
COPY verification/cluster-requirements.lock verification/runtime-requirements.lock verification/rp-requirements.lock ./
COPY deployment/build/python-wheels.lock.json /usr/share/doc/openid-python/python-wheels.lock.json
RUN --network=none --mount=type=bind,from=python-wheels,source=/wheels,target=/wheels ["python", "-m", "pip", "--isolated", "--disable-pip-version-check", "install", "--no-index", "--find-links=/wheels", "--no-cache-dir", "--require-hashes", "--only-binary=:all:", "--report=/usr/share/doc/openid-python/wheel-installation.json", "-r", "cluster-requirements.lock", "-r", "runtime-requirements.lock", "-r", "rp-requirements.lock"]
RUN --network=none ["python", "-c", "from pathlib import Path; Path('/usr/share/doc/openid-python/wheel-profile.txt').write_text('registry\\n')"]
COPY verification/cluster_bridge.py verification/federation.py verification/cluster_serve.py verification/cluster_operator.py verification/postgres.py verification/transit.py verification/maintenance.py verification/monitor.py verification/runtime.py verification/biometric_worker.py verification/serve.py verification/native.py verification/wallet.py verification/identity.py verification/crypto_runtime.py ./
COPY verification/crypto-worker.mjs verification/device-signature.mjs verification/profile-crypto.mjs ./
COPY verification/licenses /app/licenses
COPY verification/THIRD_PARTY.md /app/licenses/components.md
COPY deployment/cluster/probe.py ./probe.py
COPY verification/cluster_recovery.py verification/audit_archive.py verification/sqlite_retention.py ./
COPY verification/subject_access.py verification/postgres_subject_access.py ./
COPY verification/erasure_policy.py verification/subject_erasure.py verification/recovery_binding.py ./
COPY verification/ingress_client.py ./
COPY verification/enrollment_policy.py verification/acceptance_journal.py verification/consent_retention.py ./
COPY verification/image_input.py ./
COPY verification/bounded_process.py verification/profile_worker.py verification/worker_confinement.py ./
COPY deployment/cluster/schema.sql /app/deployment/cluster/schema.sql
COPY deployment/build/remove_build_pip.py /tmp/remove_build_pip.py
RUN --network=none ["python", "-c", "import runpy; from pathlib import Path; runpy.run_path('/tmp/remove_build_pip.py', run_name='__main__'); Path('/tmp/remove_build_pip.py').unlink()"]
COPY deployment/build/file_privileges.py /tmp/file_privileges.py
RUN --network=none ["python", "-c", "import runpy, sys; from pathlib import Path; sys.argv = ['/tmp/file_privileges.py', 'apply']; runpy.run_path('/tmp/file_privileges.py', run_name='__main__'); Path('/tmp/file_privileges.py').unlink()"]
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=6s --start-period=30s --retries=3 CMD ["python","probe.py","/srv/openid/runtime.json"]
ENTRYPOINT ["python","cluster_serve.py"]
CMD ["--config","/srv/openid/runtime.json"]
