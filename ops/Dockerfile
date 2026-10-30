# Retain the pinned Noble OS layers; replace the complete Java installation.
# The new official image tags are not published yet. This candidate is amd64.
FROM eclipse-temurin:24.0.2_12-jdk-noble@sha256:dacac8e9a0df0d2bd24e702b4431132875c249930b70555ebd7ca285b5bee684 AS compile
ADD --checksum=sha256:d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz /tmp/jdk.tar.gz
RUN test "$(dpkg --print-architecture)" = amd64 && rm -rf /opt/java/openjdk && mkdir -p /opt/java/openjdk \
    && tar -xzf /tmp/jdk.tar.gz -C /opt/java/openjdk --strip-components=1 --no-same-owner \
    && rm /tmp/jdk.tar.gz \
    && grep -Fx 'JAVA_RUNTIME_VERSION="21.0.13+9-LTS"' /opt/java/openjdk/release \
    && java -version && javac -version
ENV JAVA_VERSION=jdk-21.0.13+9
WORKDIR /build
COPY src/SealedEnvironment.java .
RUN javac --release 21 -d /classes SealedEnvironment.java

FROM eclipse-temurin:24.0.2_12-jre-noble@sha256:b416d02335e702b0403ff280de9475a3348e29382285969c9d4e17862ce632e7
ADD --checksum=sha256:a535a1df9c6284d9618872984e026ae0352d1f7e9e0605425c0e6114f47351dd https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz /tmp/jre.tar.gz
RUN test "$(dpkg --print-architecture)" = amd64 && rm -rf /opt/java/openjdk && mkdir -p /opt/java/openjdk \
    && tar -xzf /tmp/jre.tar.gz -C /opt/java/openjdk --strip-components=1 --no-same-owner \
    && rm /tmp/jre.tar.gz \
    && grep -Fx 'JAVA_RUNTIME_VERSION="21.0.13+9-LTS"' /opt/java/openjdk/release \
    && java -version
ADD --checksum=sha256:5431b6d3ad286a41d9e20b9b0d37355f430046e333b4954c0814a8c3014bd4f4 https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-sbom_x64_linux_hotspot_21.0.13_9.json /opt/java/openjdk/upstream-sbom.cdx.json
RUN chmod 644 /opt/java/openjdk/upstream-sbom.cdx.json
ENV JAVA_VERSION=jdk-21.0.13+9
LABEL org.opencontainers.image.source="https://github.com/Jtensetti/openID"
LABEL org.opencontainers.image.description="Sealed infrastructure; no e-id issuance, lab identities or test keys"
WORKDIR /app
COPY --from=compile --chown=10001:10001 /classes/ /app/
USER 10001:10001
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["java", "-cp", "/app", "SealedEnvironment", "probe"]
ENTRYPOINT ["java", "-Xms16m", "-Xmx64m", "-XX:MaxDirectMemorySize=16m", "-XX:+ExitOnOutOfMemoryError", "-Dsun.net.httpserver.maxReqTime=10", "-Dsun.net.httpserver.maxRspTime=10", "-Dsun.net.httpserver.maxReqHeaders=32", "-Dsun.net.httpserver.maxReqHeaderSize=8192", "-Djdk.httpserver.maxConnections=64", "-cp", "/app", "SealedEnvironment"]
CMD ["serve"]
