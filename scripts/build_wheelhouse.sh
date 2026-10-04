#!/usr/bin/env bash
set -euo pipefail

# Build wheelhouse for offline air-gapped deployment
echo "Downloading pinned packages into wheelhouse/..."
mkdir -p wheelhouse
pip download -r requirements.txt -d wheelhouse/
echo "Wheelhouse successfully populated in wheelhouse/"
