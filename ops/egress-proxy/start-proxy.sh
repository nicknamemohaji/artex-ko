#!/bin/sh
set -u

public_dir=/shared-ca
private_cert=/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem
public_cert=$public_dir/mitmproxy-ca-cert.pem
ready=$public_dir/ready

rm -f "$public_cert" "$public_cert.tmp" "$ready"
mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false --set stream_large_bodies=1m \
  -s /opt/artex/addon.py &
proxy_pid=$!

attempts=0
while [ ! -s "$private_cert" ]; do
  kill -0 "$proxy_pid" 2>/dev/null || { wait "$proxy_pid"; exit $?; }
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    exit 1
  fi
  sleep 0.2
done

cp "$private_cert" "$public_cert.tmp"
chmod 0444 "$public_cert.tmp"
mv "$public_cert.tmp" "$public_cert"
touch "$ready"
wait "$proxy_pid"
