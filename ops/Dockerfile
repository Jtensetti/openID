# Official Temurin images, verified 2026-10-19. Digests lock the complete multiarch image index.
FROM eclipse-temurin:21.0.12.1_1-jdk-noble@sha256:107215954359f1ab0be058a247d7c64ed6e69c71c1682d471d38ef751ec8e964 AS compile
WORKDIR /build
COPY src/SealedEnvironment.java .
RUN javac --release 21 -d /classes SealedEnvironment.java

FROM eclipse-temurin:21.0.12.1_1-jre-noble@sha256:35501d3f93173b420ac9001658eb68157e813316b865087e345c187fca422c4c
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
