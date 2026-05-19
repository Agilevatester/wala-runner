#!/usr/bin/env bash
# Build the WALA runner fat JAR.
# Run once from the project root: bash tools/wala-runner/build.sh
# Output: tools/wala-runner/target/wala-runner.jar
set -e
cd "$(dirname "$0")"
echo "[wala-runner] Building fat JAR (downloads ~80 MB of IBM WALA deps on first run)..."
mvn -q package -DskipTests
echo "[wala-runner] Done: $(pwd)/target/wala-runner.jar"
echo ""
echo "Set env to use WALA instead of SootUp:"
echo "  export JAVA_CALLGRAPH_BACKEND=wala"
echo "Or run both in parallel:"
echo "  export JAVA_CALLGRAPH_BACKEND=both"
