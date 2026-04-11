#!/bin/bash
set -e

# Create dedicated system user if it doesn't exist
if ! id -u mdns-reflector >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin mdns-reflector
fi

# Set ownership on config directory
chown -R mdns-reflector:mdns-reflector /etc/mdns-reflector
chmod 640 /etc/mdns-reflector/config.yaml

# Reload sysctl to apply IGMP limits
sysctl --system

# Load 8021q module immediately
modprobe 8021q || true

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable mdns-reflector
systemctl restart mdns-reflector
