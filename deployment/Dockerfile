# Download exact reviewed artifacts with BuildKit; pip never downloads them.
FROM scratch AS python-wheels
ADD --checksum=sha256:6667a0c21d48dc125dbba88444bc8a601ce881a99341a0e6169f9333898e620d https://files.pythonhosted.org/packages/be/bc/40dffae3238ef8d3415393132751fe2c88e8663ef84a31f0950e439ed2d5/boto3-1.43.115-py3-none-any.whl /wheels/boto3-1.43.115-py3-none-any.whl
ADD --checksum=sha256:9ceda640c868bc15f5399129e8cfdef8cbb4b350e8a99547c9b5f477cfb9619a https://files.pythonhosted.org/packages/77/2d/4b6b6f5704d1ec9b412c1dd9700bda0c315619dbac4a21418180a81a2780/botocore-1.43.115-py3-none-any.whl /wheels/botocore-1.43.115-py3-none-any.whl
ADD --checksum=sha256:7be2662e9e826b9bba28afc0f843a123280d799a2ea44bb5d35ccec67905ae44 https://files.pythonhosted.org/packages/28/00/db89d339bc4ecdc8087fa7b8607ba22ffc27bf96286f340c9620bea428b3/filelock-4.2.1-py3-none-any.whl /wheels/filelock-4.2.1-py3-none-any.whl
ADD --checksum=sha256:b57ddbafedfaef7018c1ecab32aa200a9d7ca26b77965f64e48b70061249d279 https://files.pythonhosted.org/packages/fd/3c/6a2bf344106328fd04963664a60b9bb6496fc25df8e962fcdc1367285fb9/fsspec-2026.7.0-py3-none-any.whl /wheels/fsspec-2026.7.0-py3-none-any.whl
ADD --checksum=sha256:bd249d0b3f7972f7432f0a6b6ff3b3ee2d129f70cd1ff6c09a9dd9e29a2b88e3 https://files.pythonhosted.org/packages/fe/85/7522a52e5e2f42faf1a129113ab63e548c42e103e9af395b7bfe65e403e2/gunicorn-26.2.0-py3-none-any.whl /wheels/gunicorn-26.2.0-py3-none-any.whl
ADD --checksum=sha256:85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67 https://files.pythonhosted.org/packages/62/a1/3d680cbfd5f4b8f15abc1d571870c5fc3e594bb582bc3b64ea099db13e56/jinja2-3.1.6-py3-none-any.whl /wheels/jinja2-3.1.6-py3-none-any.whl
ADD --checksum=sha256:a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64 https://files.pythonhosted.org/packages/14/2f/967ba146e6d58cf6a652da73885f52fc68001525b4197effc174321d70b4/jmespath-1.1.0-py3-none-any.whl /wheels/jmespath-1.1.0-py3-none-any.whl
ADD --checksum=sha256:d6dd0be5b5b189d31db7cda48b91d7e0a9795f31430b7f271219ab30f1d3ac9d https://files.pythonhosted.org/packages/3c/2e/8d0c2ab90a8c1d9a24f0399058ab8519a3279d1bd4289511d74e909f060e/markupsafe-3.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl /wheels/markupsafe-3.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
ADD --checksum=sha256:a0b2b9fe80bbcd81a6647ff13108738cfb482d481d826cc0e02f5b35e5c88d2c https://files.pythonhosted.org/packages/43/e3/7d92a15f894aa0c9c4b49b8ee9ac9850d6e63b03c9c32c0367a13ae62209/mpmath-1.3.0-py3-none-any.whl /wheels/mpmath-1.3.0-py3-none-any.whl
ADD --checksum=sha256:d47fbf302e7d9cbbb9e2555a0d267983d2aa476bac30e90dfbe5669bd57f3762 https://files.pythonhosted.org/packages/9e/c9/b2622292ea83fbb4ec318f5b9ab867d0a28ab43c5717bb85b0a5f6b3b0a4/networkx-3.6.1-py3-none-any.whl /wheels/networkx-3.6.1-py3-none-any.whl
ADD --checksum=sha256:fd83c01228a688733f1ded5201c678f0c53ecc1006ffbc404db9f7a899ac6249 https://files.pythonhosted.org/packages/8c/3d/1e1db36cfd41f895d266b103df00ca5b3cbe965184df824dec5c08c6b803/numpy-2.2.6-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl /wheels/numpy-2.2.6-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
ADD --checksum=sha256:211e581f5a4670acbbe08fff36a35e9946039d2eea28b80394632d036d1be527 https://files.pythonhosted.org/packages/ae/ce/7f538891722a4f06921419d55bac6f41729258d54442861edb2de0dbdf5e/opencv_python_headless-4.14.0.94-cp37-abi3-manylinux_2_28_x86_64.whl /wheels/opencv_python_headless-4.14.0.94-cp37-abi3-manylinux_2_28_x86_64.whl
ADD --checksum=sha256:a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427 https://files.pythonhosted.org/packages/ec/57/56b9bcc3c9c6a792fcbaf139543cee77261f3651ca9da0c93f5c1221264b/python_dateutil-2.9.0.post0-py2.py3-none-any.whl /wheels/python_dateutil-2.9.0.post0-py2.py3-none-any.whl
ADD --checksum=sha256:16e64e0716c14960108e85d853062c9e8bba5ca8252c0b4d0231b9df4060ff4f https://files.pythonhosted.org/packages/dd/b8/d2d6d731733f51684bbf76bf34dab3b70a9148e8f2cef2bb544fccec681a/qrcode-8.2-py3-none-any.whl /wheels/qrcode-8.2-py3-none-any.whl
ADD --checksum=sha256:24eb7535804306355e31c952a90022bf5b2f9d760f9a11062c7493a217c08553 https://files.pythonhosted.org/packages/e2/a4/88f9e10498759121060b8050a1554753dfc04df39bbbcc7aad9ecc8d9440/s3transfer-0.19.3-py3-none-any.whl /wheels/s3transfer-0.19.3-py3-none-any.whl
ADD --checksum=sha256:5231689c6ac8156cd155cfb98c3fd6fb252c3e7e9bd3d78b64d3c55f132624c9 https://files.pythonhosted.org/packages/18/02/b4bbb90f8f29e334898ff45c6d9b1fffaa6f378017052b3023a06262b5f7/setuptools-84.1.0-py3-none-any.whl /wheels/setuptools-84.1.0-py3-none-any.whl
ADD --checksum=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274 https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl /wheels/six-1.17.0-py2.py3-none-any.whl
ADD --checksum=sha256:e091cc3e99d2141a0ba2847328f5479b05d94a6635cb96148ccb3f34671bd8f5 https://files.pythonhosted.org/packages/a2/09/77d55d46fd61b4a135c444fc97158ef34a095e5681d0a6c10b75bf356191/sympy-1.14.0-py3-none-any.whl /wheels/sympy-1.14.0-py3-none-any.whl
ADD --checksum=sha256:4ca4a9394b0c771238a4f73590fdbbc4debad85ed0fa63d026ae1b085da7d6e2 https://download-r2.pytorch.org/whl/cpu/torch-2.13.0%2Bcpu-cp312-cp312-manylinux_2_28_x86_64.whl /wheels/torch-2.13.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl
ADD --checksum=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8 https://files.pythonhosted.org/packages/49/d3/b8441a820a491ddfc024b0b0cf0393375b75ea13866d9c66727e54c2fc80/typing_extensions-4.16.0-py3-none-any.whl /wheels/typing_extensions-4.16.0-py3-none-any.whl
ADD --checksum=sha256:0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3 https://files.pythonhosted.org/packages/92/9d/c4e665119135114480843e7ab388fa94d8480650450e6f8e26b70d323a4c/urllib3-2.8.0-py3-none-any.whl /wheels/urllib3-2.8.0-py3-none-any.whl

FROM python:3.12.15-trixie@sha256:0d0db5b17f11b1b7d1aafa74ceadaa64ba0944b267ff6fc22008a197acd6b9ad AS python-build
ADD --checksum=sha256:b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz /tmp/python-source.tar.xz
ADD --checksum=sha256:6c268edc3c8b9b12a875b3d3ed2495983b8a4a94c070927863b942722a9a216c https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz.spdx.json /tmp/python-source.spdx.json
COPY deployment/build/build_python.sh /build-python.sh
COPY deployment/build/patch_python_test.py /patch-python-test.py
COPY deployment/build/python-runtime.lock.json /tmp/python-runtime.lock.json
COPY deployment/build/licenses/docker-library-python-LICENSE.txt /tmp/docker-library-python-LICENSE
RUN --network=none bash /build-python.sh

FROM python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS python-base
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
FROM python-base AS pilot
LABEL org.opencontainers.image.source="https://github.com/Jtensetti/openID"
LABEL org.opencontainers.image.description="Private iPhone verification pilot"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 JAVA_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:$PATH"
COPY --from=java-runtime /opt/java/openjdk /opt/java/openjdk
COPY --from=node-build /usr/local/bin/node /usr/local/bin/node
COPY --from=node-build /usr/local/LICENSE /usr/share/doc/nodejs/LICENSE
WORKDIR /app/verification
COPY verification/requirements.lock verification/rp-requirements.lock verification/runtime-requirements.lock ./
COPY deployment/aws/requirements.lock /app/aws-requirements.lock
COPY deployment/build/python-wheels.lock.json /usr/share/doc/openid-python/python-wheels.lock.json
RUN --network=none --mount=type=bind,from=python-wheels,source=/wheels,target=/wheels \
    python -m pip --isolated --disable-pip-version-check install \
    --no-index --find-links=/wheels --no-cache-dir --require-hashes --only-binary=:all: \
    --report=/usr/share/doc/openid-python/wheel-installation.json -r requirements.lock -r rp-requirements.lock -r runtime-requirements.lock -r /app/aws-requirements.lock
RUN --network=none printf '%s\n' pilot > /usr/share/doc/openid-python/wheel-profile.txt
COPY --from=node-build /app/verification/node_modules ./node_modules
COPY --from=java-verified /check/target/isolated-eid-lab.jar /app/prototype/target/isolated-eid-lab.jar
COPY verification/face.py verification/image_input.py verification/pad.py verification/download_models.py ./
COPY verification/bounded_process.py verification/profile_worker.py verification/worker_confinement.py ./
COPY verification/vendor ./vendor
COPY verification/licenses ./licenses
COPY prototype/licenses /app/licenses/java
COPY verification/THIRD_PARTY.md /app/licenses/verification.md
COPY THIRD_PARTY.md /app/licenses/components.md
RUN python download_models.py
COPY deployment/aws/licenses /app/licenses/aws
COPY deployment/aws/THIRD_PARTY.md deployment/aws/sbom.cdx.json /app/licenses/aws/
COPY verification/crypto_runtime.py verification/serve.py verification/runtime.py verification/biometric_worker.py verification/native.py verification/chip.py verification/server.py verification/wallet.py verification/wallet_cli.py verification/registry_binding.py verification/identity.py verification/recovery.py verification/relying_party.py ./
COPY verification/crypto-worker.mjs verification/attest.mjs verification/device-signature.mjs verification/profile-crypto.mjs ./
COPY verification/revocation.py verification/notices.py verification/notice_exporter.py verification/continuity_operator.py ./
COPY verification/audit_archive.py verification/crl_maintenance.py verification/ingress_client.py verification/sqlite_retention.py verification/recovery_binding.py ./
COPY verification/rp_web ./rp_web
COPY deployment/probe.py ./probe.py
COPY deployment/build/remove_build_pip.py /tmp/remove_build_pip.py
RUN --network=none python /tmp/remove_build_pip.py && rm /tmp/remove_build_pip.py
COPY deployment/build/file_privileges.py /tmp/file_privileges.py
RUN --network=none python /tmp/file_privileges.py apply && rm /tmp/file_privileges.py
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=3 CMD ["python", "probe.py", "/srv/openid/runtime.json"]
ENTRYPOINT ["python", "serve.py"]
CMD ["--config", "/srv/openid/runtime.json"]

# Explicit comparison target; it is not the default runtime image.
FROM python:3.12.15-trixie@sha256:0d0db5b17f11b1b7d1aafa74ceadaa64ba0944b267ff6fc22008a197acd6b9ad AS opencv-build
RUN rm -rf /usr/local
COPY --from=python-build /stage/usr/local /usr/local
RUN ldconfig
ADD --checksum=sha256:7a75663094ebd50bf212928423a24394e29d751db878044ad015ba28546a59db https://github.com/opencv/opencv/archive/0654a42e19215ef25b1d367d822f3c630447e7c7.tar.gz /inputs/opencv.tar.gz
ADD --checksum=sha256:e5bb807f7728cb60cd8b27ebc97a2edb469b68655f21e844a600c3575b76f5bb https://github.com/Kitware/CMake/releases/download/v4.4.4/cmake-4.4.4-linux-x86_64.tar.gz /inputs/cmake.tar.gz
ADD --checksum=sha256:6f30092cef9fb839779646608f4ee14ae3cbac989c47fa05e841b0841f09878e https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/3.2.0/libjpeg-turbo-3.2.0.tar.gz /inputs/jpeg.tar.gz
ADD --checksum=sha256:e723e8babb2188e8743308842bb1bfc9809f0375cd964cfeac2fb17285094321 https://github.com/uclouvain/openjpeg/archive/8314119b067c0fc77834731168daaebd379fdb12.tar.gz /inputs/openjpeg.tar.gz
COPY --from=python-wheels /wheels/numpy-2.2.6-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl /inputs/numpy.whl
COPY deployment/build/opencv/native.lock.json /inputs/native.lock.json
COPY deployment/build/opencv/build.py /build-opencv.py
RUN --network=none python /build-opencv.py

FROM pilot AS opencv-candidate
COPY --from=opencv-build /native /opt/openid-opencv
ENV PYTHONPATH=/opt/openid-opencv/python:/app/verification
LABEL io.openid.candidate-only="true"

# Preserve the reviewed default while the native replacement is evaluated.
FROM pilot AS release
