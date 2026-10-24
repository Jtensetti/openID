# Official Temurin images, verified 2026-10-19. Digests lock the complete multiarch image index.
FROM eclipse-temurin:24.0.2_12-jdk-noble@sha256:dacac8e9a0df0d2bd24e702b4431132875c249930b70555ebd7ca285b5bee684 AS compile
WORKDIR /build
COPY src/SealedEnvironment.java .
RUN javac --release 21 -d /classes SealedEnvironment.java

FROM eclipse-temurin:24.0.2_12-jre-noble@sha256:b416d02335e702b0403ff280de9475a3348e29382285969c9d4e17862ce632e7
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
