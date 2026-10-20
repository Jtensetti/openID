#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
case "${1-}" in
  build) ./mvnw -B -ntp clean verify dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt
         python3 scripts/dependencies.py ;;
  init) "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar target/isolated-eid-lab.jar init .local ;;
  start) exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar target/isolated-eid-lab.jar start .local ;;
  *) echo 'Usage: sh scripts/lab.sh build|init|start' >&2; exit 2 ;;
esac
