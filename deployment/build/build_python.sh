#!/bin/bash
# Build recipe adapted from docker-library/python (MIT); see retained license.
# CPython sources are unmodified. This runs only in the isolated amd64 builder.
set -euo pipefail
test "$(dpkg --print-architecture)" = amd64
test ! -e /stage
mkdir -p /usr/src/openid-python /stage/usr/share/doc/openid-python
tar -xJf /tmp/python-source.tar.xz -C /usr/src/openid-python --strip-components=1 --no-same-owner
cd /usr/src/openid-python
grep -Fx '#define PY_VERSION              "3.12.16"' Include/patchlevel.h

# Match the slim runtime's native modules; the full builder also has Tk headers.
export py_cv_module__tkinter=disabled
./configure --build="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)" \
    --enable-option-checking=fatal --enable-shared --enable-optimizations \
    --enable-loadable-sqlite-extensions --with-lto --with-ensurepip=install
compile_flags="$(dpkg-buildflags --get CFLAGS) -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer"
link_flags="$(dpkg-buildflags --get LDFLAGS)"
make -j2 "EXTRA_CFLAGS=$compile_flags" "LDFLAGS=$link_flags"
# Bind the installed interpreter to its own libpython, not the builder's 3.12.15.
rm python
make -j2 "EXTRA_CFLAGS=$compile_flags" "LDFLAGS=$link_flags -Wl,-rpath='\$\$ORIGIN/../lib'" python
export LD_LIBRARY_PATH="$PWD"
./python -c 'import sys, pyexpat; assert sys.version_info[:3] == (3,12,16); assert pyexpat.EXPAT_VERSION == "expat_2.9.0"'
./python -m test -j2 --timeout=180 test_ssl test_hashlib test_sqlite3 \
    test_pyexpat test_xml_etree test_tarfile test_tempfile test_http_cookiejar \
    2>&1 | tee /stage/usr/share/doc/openid-python/upstream-tests.log
make -j2 DESTDIR=/stage install

cp LICENSE /stage/usr/share/doc/openid-python/LICENSE
cp Doc/license.rst /stage/usr/share/doc/openid-python/third-party-licenses.rst
cp Modules/expat/COPYING /stage/usr/share/doc/openid-python/Expat-COPYING
cp /tmp/python-source.spdx.json /stage/usr/share/doc/openid-python/source.spdx.json
cp /tmp/python-runtime.lock.json /stage/usr/share/doc/openid-python/build-lock.json
cp /tmp/docker-library-python-LICENSE /stage/usr/share/doc/openid-python/docker-library-python-LICENSE
printf '%s\n' 'CPython 3.12.16: unmodified official source; Debian 13 amd64 build.' \
    'Build configuration, install staging and test-file pruning are maintained by openID.' \
    > /stage/usr/share/doc/openid-python/BUILD-NOTICE.txt
find /stage/usr/local -depth \( \( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
    -o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' -o -name 'libpython*.a' \) \) \) -exec rm -rf '{}' +
for name in python pip pydoc; do ln -s "${name}3" "/stage/usr/local/bin/$name"; done
chmod -R a+rX /stage/usr/share/doc/openid-python
