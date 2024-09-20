#!/bin/sh

touch /tmp/SCRIPT_FUNCIONANDO #Testing

iptables -F INPUT
iptables -F OUTPUT
iptables -F FORWARD

iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

#TODO Extra actions on whole subnet

exit 0
