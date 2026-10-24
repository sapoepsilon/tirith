#!/usr/bin/env bash
# Port shim for the parallel Metasploitable 3 box (guest 163, 192.168.50.129) on the pve3 host
# (192.168.50.161): the second box runs the same port map as the breach lab, so it is published on
# 81xx instead of 8x. 8162 is the one entry in Tirith's scope (backend/scope.yaml), for its web root.
#
#   scp provision/meta3-shim.sh root@192.168.50.161:/opt/tirith/provision/
#   ssh root@192.168.50.161 bash /opt/tirith/provision/meta3-shim.sh
#
# Idempotent and read-only: socat forwards TCP, nothing is stateful on the host. The unit is enabled so a host
# reboot brings the ports back; it stays up while the guest is down (the forward refuses until the guest is up).
# The guest's provisioner restarts Apache, and a fresh listen queue stalls while a half-open LAN connection to
# the guest lingers in the host (sshfs etc.) -- the check below retries for APACHE_RETRIES x APACHE_SLEEP sec.
# After the fact: `curl -sI http://192.168.50.161:8162/` -> refused while the guest is down, Apache once up.
set -euo pipefail

GUEST="${GUEST:-192.168.50.129}"
UNIT=meta3-shim.service
MAPS=(8162:80 8121:21 8145:445 8101:3306 8161:8080 8168:8088 8190:9090)
RETRIES="${APACHE_RETRIES:-20}" SLEEP="${APACHE_SLEEP:-1}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ "$GUEST" =~ ^[0-9.]+$ ]] || { echo "GUEST must be an IPv4 address" >&2; exit 1; }
command -v socat >/dev/null || apt-get -y -o DPkg::Lock::Timeout=300 install socat >/dev/null

# A target manages independent, restartable forwards; one blocked listener cannot stall its siblings.
for m in "${MAPS[@]}"; do
  port="${m%%:*}"
  cat >"/etc/systemd/system/meta3-shim-$port.service" <<EOF
[Unit]
Description=Metasploitable forward $port
PartOf=meta3-shim.service
After=network-online.target
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:$port,fork,reuseaddr TCP:$GUEST:${m##*:},connect-timeout=3
Restart=always
RestartSec=2
EOF
done
{
  printf '%s\n' '[Unit]' "Description=Metasploitable forwards ($GUEST)" 'After=network-online.target' 'Wants=network-online.target'
  for m in "${MAPS[@]}"; do printf 'Wants=meta3-shim-%s.service\n' "${m%%:*}"; done
  printf '%s\n' '[Service]' 'Type=oneshot' 'RemainAfterExit=yes' 'ExecStart=/usr/bin/true' '[Install]' 'WantedBy=multi-user.target'
} >"/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemctl enable "$UNIT"
systemctl restart "$UNIT"
for m in "${MAPS[@]}"; do systemctl restart "meta3-shim-${m%%:*}.service"; done
systemctl --no-pager --lines=0 status "$UNIT"
for ((i=0; i<RETRIES; i++)); do
  if curl -sS -I --max-time 4 http://127.0.0.1:8162/ > /run/meta3-shim-http-check &&
     grep -Eq '^HTTP/[0-9.]+ [1-5][0-9][0-9]' /run/meta3-shim-http-check; then
    cat /run/meta3-shim-http-check
    exit 0
  fi
  sleep "$SLEEP"
done
echo "8162 listener installed, but no HTTP answer from $GUEST:80; check the guest Apache service/address" >&2
exit 1
