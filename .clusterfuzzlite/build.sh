#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# Every third-party package comes from a hash-pinned lock. witness.txt pulls
# in runtime.txt, and ci.txt carries hatchling, so the package itself can go
# in with --no-deps --no-build-isolation and nothing unpinned is resolved,
# not even the build backend.

cd "$SRC/trace-registry"
pip3 install --no-cache-dir --require-hashes -r requirements/witness.txt
pip3 install --no-cache-dir --require-hashes -r requirements/ci.txt
pip3 install --no-cache-dir --no-deps --no-build-isolation .

# Seed corpora from committed fixtures (samples/, registry/, docs/evidence/).
python3 .clusterfuzzlite/seed_corpora.py "$OUT"

PYI_ARGS=(
  # compile_python_fuzzer bundles each target with PyInstaller, which follows
  # static imports only. The cryptography stack reaches email.mime lazily, so
  # without this the bundled target dies at runtime with
  # "ModuleNotFoundError: No module named 'email.mime'" and libFuzzer reports
  # it as a crash in the target.
  --collect-submodules=email
  # aggregator/ and tools/ are not part of the installed package. The intake
  # target fuzzes them, so PyInstaller has to find them from the checkout.
  --paths="$SRC/trace-registry"
  --paths="$SRC/trace-registry/tools"
)

for target in "$SRC"/trace-registry/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done
