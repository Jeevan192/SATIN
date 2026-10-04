#!/usr/bin/env bash
set -euo pipefail

# Air-gapped offline installation from local wheelhouse
echo "Installing SAT-SA dependencies from local wheelhouse (offline mode)..."
if [ ! -d "wheelhouse" ]; then
    echo "ERROR: wheelhouse/ directory not found. Please provide pre-packaged wheelhouse." >&2
    exit 1
fi
pip install --no-index --find-links wheelhouse -r requirements.txt
echo "Offline installation complete."
