#!/bin/sh
set -e

# remove keeps the config and the user so a reinstall picks up where it left
# off; purge deletes both.
case "$1" in
    remove)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi
        ;;
    purge)
        rm -rf /etc/mdns-reflector
        if id -u mdns-reflector >/dev/null 2>&1; then
            userdel mdns-reflector || true
        fi
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi
        ;;
esac
