#!/bin/sh
# Start IDPS with the project's virtual environment. Extra arguments are passed through.
#
# The GUI needs root for live capture and the inline IPS, so when it is started by a normal user this script
# asks for the sudo password first and opens the window only after it is accepted. Command-line modes
# (--headless, --self-test, --list-interfaces, --wifi-scan, --help, --version) run as you; add sudo yourself
# when they need root (for example live headless capture).
# To open the GUI without root (simulation, PCAP replay and Wi-Fi only): IDPS_NO_SUDO=1 ./run.sh
here=$(cd "$(dirname "$0")" && pwd)
python="$here/.venv/bin/python"
if [ ! -x "$python" ]; then
    echo "IDPS's virtual environment was not found in $here/.venv."
    echo "Create it once from this folder with:"
    echo "    python3 -m venv .venv"
    echo "    .venv/bin/pip install -r requirements.txt"
    exit 1
fi

gui=1
for arg in "$@"; do
    case "$arg" in
        --headless|--self-test|--list-interfaces|--wifi-scan|-h|--help|--version) gui=0 ;;
    esac
done

if [ "$gui" = 1 ] && [ "$(id -u)" != 0 ] && [ -z "$IDPS_NO_SUDO" ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "sudo is not installed. Start IDPS as root, or without root: IDPS_NO_SUDO=1 ./run.sh"
        exit 1
    fi
    if [ -z "$DISPLAY" ]; then
        echo "No graphical display found (DISPLAY is not set), so the IDPS window cannot open."
        echo "Run it from a terminal on the desktop, or use headless mode: ./run.sh --headless --help"
        exit 1
    fi
    echo "IDPS needs root for live capture and the inline IPS. Enter your password to open it."
    # Ask for the password now, so the window opens only after it was accepted.
    if ! sudo -v; then
        echo "The password was not accepted, so IDPS was not started."
        echo "To open it without root (simulation, PCAP replay and Wi-Fi only): IDPS_NO_SUDO=1 ./run.sh"
        exit 1
    fi
    # Root may draw on this desktop through X11: pass the display and its access cookie. WAYLAND_DISPLAY is
    # left out on purpose, so Qt uses X11 (XWayland) instead of a Wayland socket root cannot reach.
    # -H: root keeps its own data folder (/root/.netsentinel). PYTHONDONTWRITEBYTECODE: no root-owned
    # __pycache__ folders in this project.
    exec sudo -H env DISPLAY="$DISPLAY" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=xcb "$python" "$here/idps.py" "$@"
fi
exec "$python" "$here/idps.py" "$@"
