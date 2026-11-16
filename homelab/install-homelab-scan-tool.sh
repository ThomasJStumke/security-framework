#!/bin/bash
# Installs homelab-scan-tool so the isolated runner account can run the security scanners
# (ZAP, Gitleaks, Semgrep, Nuclei) without being in the docker group. Safe to run again.
#
#   sudo bash install-homelab-scan-tool.sh
#
# Puts the script at /usr/local/sbin/homelab-scan-tool (root:root 755) and adds one sudoers rule:
#   ghrunner ALL=(root) NOPASSWD: /usr/local/sbin/homelab-scan-tool
# The rule is checked with visudo before it goes live, so a mistake can't lock sudo out.
set -euo pipefail
[ "$(id -u)" = 0 ] || exec sudo bash "$0" "$@"
here="$(cd "$(dirname "$0")" && pwd)"
RUN_USER=ghrunner
id "$RUN_USER" >/dev/null 2>&1 || { echo "user $RUN_USER not found"; exit 1; }

install -m 755 -o root -g root "$here/homelab-scan-tool" /usr/local/sbin/homelab-scan-tool.new
mv /usr/local/sbin/homelab-scan-tool.new /usr/local/sbin/homelab-scan-tool

rule="$RUN_USER ALL=(root) NOPASSWD: /usr/local/sbin/homelab-scan-tool"
tmp=$(mktemp); printf '%s\n' "# Security scanners for the isolated GitHub runners (security-framework)" "$rule" > "$tmp"
visudo -cf "$tmp" >/dev/null
install -m 440 -o root -g root "$tmp" /etc/sudoers.d/homelab-scan-tool; rm -f "$tmp"
visudo -c >/dev/null

echo "Installed. Check as the runner user:"
sudo -u "$RUN_USER" sudo -n /usr/local/sbin/homelab-scan-tool check
for img in zricethezav/gitleaks:v8.18.4 semgrep/semgrep:1.78.0 projectdiscovery/nuclei:v3.11.1 ghcr.io/zaproxy/zaproxy:stable; do
  docker pull -q "$img" >/dev/null && echo "  image ready: $img"
done
