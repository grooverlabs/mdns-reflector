#!/bin/bash
set -e

# Reload sysctl to apply IGMP limits
sysctl --system

# Load 8021q module immediately
modprobe 8021q || true

# Reload systemd and enable service
chmod 644 /etc/mdns-reflector/config.yaml
systemctl daemon-reload
systemctl enable mdns-reflector
systemctl restart mdns-reflector
