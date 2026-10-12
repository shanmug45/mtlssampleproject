#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/certificates"}
PASSWORD=${2:-changeit}

cd "$ROOT_DIR"
mvn -q -pl common -am compile
java -cp common/target/classes dev.samplemtls.common.CertificateBundleGenerator "$OUTPUT_DIR" "$PASSWORD"
