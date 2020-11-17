#!/bin/bash

#	Author 	: Prabesh Thapa
#	Date	: July 19, 2016 

# nating with two ethernet devices

function check_root(){
	if [ $USER == 'root' ]
	then
		iptable_firewall
		iptable_save
	else
		echo "Error : You need root access to execute the script."
	fi
}


function iptable_firewall(){
	echo ""
	echo "[*] NAT Firewall"
	iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT

	echo "[*] Allow Loopback"
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT

	echo "[*] Allow incoming connections"
	iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	echo "[*] Allow outgoing connection"
	iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

	echo "[*] Drop invalid packets"
	iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

	echo "[*] Block IP"
	# iptables -A INPUT -s XX.XX.XX.XX -j DROP

	echo "[*] Allow SSH"
	iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

	echo "[*] Block invalid packets"
	iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

	echo "[*] Block SYN flood"
	iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

	echo "[*] Block uncommon MSS value"
	iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

	echo "[*] Bogus TCP packets"
	iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
	iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
	iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
	iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
	iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
	iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
	iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP

	echo "[*] Protect IP spoofing"
	iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
	iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
	iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
	iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
	iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
	iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
	iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
	iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
	iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

	echo "[*] ICPM DROP"
	iptables -t mangle -A PREROUTING -p icmp -j DROP

	echo "[*] Connection Attack"
	iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

	echo "[*] Limit TCP connection"
	iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
	iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

	echo "[*] SYN Flood protect"
	iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
	iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 
	iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

	echo "Brute force protection"
	iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
	iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

	echo "Port scanning"
	iptables -N port-scanning
	iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
	iptables -A port-scanning -j DROP
}

function iptable_save(){
	echo ""
	echo "[*] Saving the rules"
	iptables-save
	#iptables-save > /etc/sysconfig/iptables
}

check_root
