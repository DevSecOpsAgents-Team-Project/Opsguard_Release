#!/usr/bin/env bash
# Finance Agent Lambda 배포 zip (Linux/macOS 또는 CI)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PYTHON_VERSION="${PYTHON_VERSION:-3.11}"
OUTPUT="${OUTPUT:-finance-agent.zip}"
PACKAGE_DIR="$ROOT/package"

echo "==> Finance Agent Lambda package build (Python $PYTHON_VERSION)"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

pip install -r "$ROOT/requirements.txt" -t "$PACKAGE_DIR" \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version "$PYTHON_VERSION" \
  --only-binary=:all: \
  --upgrade

cp "$ROOT/handler.py" "$PACKAGE_DIR/"
cp -r "$ROOT/src" "$ROOT/policy" "$PACKAGE_DIR/"
[ -d "$ROOT/schemas" ] && cp -r "$ROOT/schemas" "$PACKAGE_DIR/"

cd "$PACKAGE_DIR"
rm -f "$ROOT/$OUTPUT"
zip -r "$ROOT/$OUTPUT" .

echo "Done: $ROOT/$OUTPUT"
echo "Handler: handler.lambda_handler | Runtime: Python $PYTHON_VERSION"
