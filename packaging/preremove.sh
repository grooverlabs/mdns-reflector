#!/bin/sh
set -e

# dpkg passes $1 = remove | upgrade | deconfigure | failed-upgrade (never
# "purge"; that goes to postremove). Don't stop on upgrade; postinstall
# restarts.
if [ "$1" != "upgrade" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop mdns-reflector.service >/dev/null 2>&1 || true
    systemctl disable mdns-reflector.service >/dev/null 2>&1 || true
fi
