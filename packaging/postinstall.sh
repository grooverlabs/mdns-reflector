#!/bin/sh
set -e

# Create the service user
if ! id -u mdns-reflector >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin mdns-reflector
fi

# Config: copy the example on first install only; never touch an existing
# config.yaml. The live config is root:mdns-reflector 0640.
mkdir -p /etc/mdns-reflector
if [ ! -f /etc/mdns-reflector/config.yaml ] && [ -f /etc/mdns-reflector/config.yaml.example ]; then
    cp /etc/mdns-reflector/config.yaml.example /etc/mdns-reflector/config.yaml
    echo "mdns-reflector: edit /etc/mdns-reflector/config.yaml, then: systemctl restart mdns-reflector"
fi
if [ -f /etc/mdns-reflector/config.yaml ]; then
    chown root:mdns-reflector /etc/mdns-reflector/config.yaml
    chmod 0640 /etc/mdns-reflector/config.yaml
fi
chown root:mdns-reflector /etc/mdns-reflector
chmod 0750 /etc/mdns-reflector

# The socket joins the mDNS group once per interface; Linux allows 20 groups
# per socket by default. Raise the limit only if it is lower than ours.
want=$(sed -n 's/^net\.ipv4\.igmp_max_memberships *= *//p' /etc/sysctl.d/mdns-reflector.conf)
have=$(sysctl -n net.ipv4.igmp_max_memberships 2>/dev/null || echo 0)
if command -v sysctl >/dev/null 2>&1 && [ -n "$want" ] && [ "$have" -lt "$want" ]; then
    sysctl -q -p /etc/sysctl.d/mdns-reflector.conf || echo "mdns-reflector: could not apply /etc/sysctl.d/mdns-reflector.conf"
fi

# VLAN sub-interfaces need 8021q (loaded at boot by modules-load.d)
modprobe 8021q 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable mdns-reflector.service >/dev/null 2>&1 || true
    # restart, not start: start leaves the old binary running on upgrade.
    # A config the new version rejects must not fail the package install.
    systemctl restart mdns-reflector.service || \
        echo "mdns-reflector: service did not start; see: journalctl -u mdns-reflector"
fi
