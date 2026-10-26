FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS python-base
COPY deployment/build/patch_bookworm.py deployment/build/bookworm-updates.lock.json /tmp/openid-os-patches/
RUN python /tmp/openid-os-patches/patch_bookworm.py && rm -rf /tmp/openid-os-patches

FROM python-base AS maven-tool
RUN python -c "import urllib.request,hashlib,zipfile,io; data=urllib.request.urlopen('https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip').read(); assert hashlib.sha256(data).hexdigest()=='0d7125e8c91097b36edb990ea5934e6c68b4440eef4ea96510a0f6815e7eeadb'; zipfile.ZipFile(io.BytesIO(data)).extractall('/opt')"
RUN chmod +x /opt/apache-maven-3.9.11/bin/mvn

# The official versioned container tags are not yet available. Use the exact
# upstream Linux x64 distribution, checked by BuildKit before extraction.
FROM python-base AS java-build
ADD --checksum=sha256:d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz /tmp/jdk.tar.gz
RUN test "$(dpkg --print-architecture)" = amd64 && mkdir -p /opt/java/openjdk \
    && tar --extract --gzip --file /tmp/jdk.tar.gz --directory /opt/java/openjdk --strip-components=1 --no-same-owner \
    && rm /tmp/jdk.tar.gz \
    && grep -Fx 'JAVA_RUNTIME_VERSION="21.0.13+9-LTS"' /opt/java/openjdk/release
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:$PATH"
RUN java -version && javac -version
COPY --from=maven-tool /opt/apache-maven-3.9.11 /opt/maven
WORKDIR /build/prototype
COPY prototype/pom.xml prototype/mvnw ./
COPY prototype/.mvn .mvn
COPY prototype/src/main src/main
RUN /opt/maven/bin/mvn -B -ntp -Dmaven.test.skip=true package dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt

FROM maven-tool AS java-verified
COPY --from=java-build /root/.m2 /root/.m2
COPY --from=java-build /build/prototype/target /check/target
COPY prototype/dependencies.lock.json /check/dependencies.lock.json
COPY prototype/scripts/dependencies.py /check/scripts/dependencies.py
RUN python /check/scripts/dependencies.py

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS node-build
WORKDIR /app/verification
COPY verification/package.json verification/package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev

FROM python-base AS java-runtime
ADD --checksum=sha256:a535a1df9c6284d9618872984e026ae0352d1f7e9e0605425c0e6114f47351dd https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz /tmp/jre.tar.gz
RUN test "$(dpkg --print-architecture)" = amd64 && mkdir -p /opt/java/openjdk \
    && tar --extract --gzip --file /tmp/jre.tar.gz --directory /opt/java/openjdk --strip-components=1 --no-same-owner \
    && rm /tmp/jre.tar.gz \
    && grep -Fx 'JAVA_RUNTIME_VERSION="21.0.13+9-LTS"' /opt/java/openjdk/release \
    && /opt/java/openjdk/bin/java -version
ADD --checksum=sha256:5431b6d3ad286a41d9e20b9b0d37355f430046e333b4954c0814a8c3014bd4f4 https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-sbom_x64_linux_hotspot_21.0.13_9.json /opt/java/openjdk/upstream-sbom.cdx.json
RUN chmod 644 /opt/java/openjdk/upstream-sbom.cdx.json
FROM python-base
LABEL org.opencontainers.image.source="https://github.com/Jtensetti/openID"
LABEL org.opencontainers.image.description="Private iPhone verification pilot"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 JAVA_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:$PATH"
COPY --from=java-runtime /opt/java/openjdk /opt/java/openjdk
COPY --from=node-build /usr/local/bin/node /usr/local/bin/node
COPY --from=node-build /usr/local/LICENSE /usr/share/doc/nodejs/LICENSE
WORKDIR /app/verification
COPY verification/requirements.lock verification/rp-requirements.lock verification/runtime-requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r rp-requirements.lock -r runtime-requirements.lock
COPY --from=node-build /app/verification/node_modules ./node_modules
COPY --from=java-verified /check/target/isolated-eid-lab.jar /app/prototype/target/isolated-eid-lab.jar
COPY verification/face.py verification/pad.py verification/download_models.py ./
COPY verification/vendor ./vendor
COPY verification/licenses ./licenses
COPY prototype/licenses /app/licenses/java
COPY verification/THIRD_PARTY.md /app/licenses/verification.md
COPY THIRD_PARTY.md /app/licenses/components.md
RUN python download_models.py
COPY deployment/aws/requirements.lock /app/aws-requirements.lock
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /app/aws-requirements.lock
COPY deployment/aws/licenses /app/licenses/aws
COPY deployment/aws/THIRD_PARTY.md deployment/aws/sbom.cdx.json /app/licenses/aws/
COPY verification/crypto_runtime.py verification/serve.py verification/runtime.py verification/biometric_worker.py verification/native.py verification/chip.py verification/server.py verification/wallet.py verification/wallet_cli.py verification/registry_binding.py verification/identity.py verification/recovery.py verification/relying_party.py ./
COPY verification/crypto-worker.mjs verification/attest.mjs verification/device-signature.mjs verification/profile-crypto.mjs ./
COPY verification/revocation.py verification/notices.py verification/notice_exporter.py verification/continuity_operator.py ./
COPY verification/audit_archive.py ./
COPY verification/rp_web ./rp_web
COPY deployment/probe.py ./probe.py
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=3 CMD ["python", "probe.py", "/srv/openid/runtime.json"]
ENTRYPOINT ["python", "serve.py"]
CMD ["--config", "/srv/openid/runtime.json"]
