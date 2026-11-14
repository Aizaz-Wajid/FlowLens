#!/bin/bash
# FlowLens lab: two isolated network stacks joined by a virtual cable
#   cli = client  10.0.0.1      srv = server  10.0.0.2
# Run with:  sudo ./lab_setup.sh      (run again after every WSL restart)

ip netns del cli 2>/dev/null; ip netns del srv 2>/dev/null
ip netns add cli
ip netns add srv
ip link add veth-cli type veth peer name veth-srv
ip link set veth-cli netns cli
ip link set veth-srv netns srv
ip netns exec cli ip addr add 10.0.0.1/24 dev veth-cli
ip netns exec srv ip addr add 10.0.0.2/24 dev veth-srv
for ns in cli srv; do ip netns exec $ns ip link set lo up; done
ip netns exec cli ip link set veth-cli up
ip netns exec srv ip link set veth-srv up

# Real packet sizes in captures (no offloading)
ip netns exec cli ethtool -K veth-cli gro off gso off tso off >/dev/null 2>&1
ip netns exec srv ethtool -K veth-srv gro off gso off tso off >/dev/null 2>&1

# Client's DNS goes straight to the lab DNS server (no cache, no systemd-resolved)
mkdir -p /etc/netns/cli
echo "nameserver 10.0.0.2" > /etc/netns/cli/resolv.conf
sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf > /etc/netns/cli/nsswitch.conf

echo "Lab ready: client 10.0.0.1  <->  server 10.0.0.2"
