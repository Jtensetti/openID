FROM python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS maven-tool
RUN python -c "import urllib.request,hashlib,zipfile,io; data=urllib.request.urlopen('https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip').read(); assert hashlib.sha256(data).hexdigest()=='0d7125e8c91097b36edb990ea5934e6c68b4440eef4ea96510a0f6815e7eeadb'; zipfile.ZipFile(io.BytesIO(data)).extractall('/opt')"
RUN chmod +x /opt/apache-maven-3.9.11/bin/mvn

FROM eclipse-temurin:21.0.12.1_1-jdk-noble@sha256:107215954359f1ab0be058a247d7c64ed6e69c71c1682d471d38ef751ec8e964 AS java-build
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

FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS node-build
WORKDIR /app/verification
COPY verification/package.json verification/package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev

FROM eclipse-temurin:21.0.12.1_1-jre-noble@sha256:35501d3f93173b420ac9001658eb68157e813316b865087e345c187fca422c4c AS java-runtime
FROM python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
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
COPY verification/ingress_client.py ./
COPY verification/rp_web ./rp_web
COPY deployment/probe.py ./probe.py
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=3 CMD ["python", "probe.py", "/srv/openid/runtime.json"]
ENTRYPOINT ["python", "serve.py"]
CMD ["--config", "/srv/openid/runtime.json"]
