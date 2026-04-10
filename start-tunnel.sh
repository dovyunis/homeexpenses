#!/bin/bash
# Start localhost.run tunnel with SSH key (permanent URL)
# URL: https://5660d58f2cc224.lhr.life

kill $(pgrep -f 'localhost.run') 2>/dev/null
sleep 1

ssh -o StrictHostKeyChecking=no \
    -o ServerAliveInterval=60 \
    -o ServerAliveCountMax=3 \
    -i ~/.ssh/id_ed25519 \
    -R 80:localhost:3000 \
    localhost.run < /dev/null > /tmp/tunnel.log 2>&1 &

echo "Tunnel started! PID: $!"
echo "URL: https://5660d58f2cc224.lhr.life"
echo "https://5660d58f2cc224.lhr.life" > ~/tunnel-url.txt
