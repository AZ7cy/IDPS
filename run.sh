#!/bin/sh
# Start IDPS with the project's virtual environment. Extra arguments are passed through.
# Live capture and the inline IPS need root (or the cap_net_raw,cap_net_admin capabilities).
here=$(cd "$(dirname "$0")" && pwd)
python="$here/.venv/bin/python"
if [ ! -x "$python" ]; then
    echo "IDPS's virtual environment was not found in $here/.venv."
    echo "Create it once from this folder with:"
    echo "    python3 -m venv .venv"
    echo "    .venv/bin/pip install -r requirements.txt"
    exit 1
fi
exec "$python" "$here/idps.py" "$@"
