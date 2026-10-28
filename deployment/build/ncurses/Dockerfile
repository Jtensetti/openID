FROM python:3.12.15-trixie@sha256:0d0db5b17f11b1b7d1aafa74ceadaa64ba0944b267ff6fc22008a197acd6b9ad
ENV OPENID_PACKAGE_CANDIDATE_BUILD=1 OPENID_NCURSES_CANDIDATE_BUILD=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY util_linux/bootstrap.py util_linux/build.py util_linux/test_signature_policy.py /builder/
COPY util_linux/fixtures/signature-policy/ /builder/fixtures/signature-policy/
COPY ncurses/candidate.lock.json ncurses/candidate.py ncurses/compatibility.py ncurses/inventory.py /builder/
COPY ncurses/Dockerfile ncurses/Dockerfile.dockerignore /builder/
RUN python /builder/bootstrap.py
ARG BUILDER_UID=10001
ARG BUILDER_GID=10001
RUN groupadd --gid "$BUILDER_GID" candidate \
    && useradd --uid "$BUILDER_UID" --gid "$BUILDER_GID" --home-dir /output --no-create-home candidate
USER candidate
WORKDIR /output
ENTRYPOINT ["python", "/builder/candidate.py", "build", "--inputs", "/inputs", "--output", "/output"]
