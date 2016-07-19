#!/bin/bash

#	Author 	: Prabesh Thapa
#	Date	: July 19, 2016 

# nating with two ethernet devices

function check_root(){
	if [ $USER == 'root' ]
	then
		iptable_flush
		iptable_nat
		iptable_save
		port_forward
	else
		echo "Error : You need root access to execute the script."
	fi
}

#iptables --flush

function iptable_flush(){
	echo ""
	echo "************************ Performing Network Address Translation (NAT) **************************"
	echo ""
	echo "[*] Flushing the previous rules"
	iptables --flush
	echo "   - Flushing nat table rules"
	iptables --table nat --flush
	echo "   - Deleting previous chains"
	iptables --delete-chain

}

function iptable_nat(){
	echo ""
	echo "[*] IP Forward and Masquerading"
	iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
}

function iptable_save(){
	echo ""
	echo "[*] Saving the rules"
	iptables-save
	#iptables-save > /etc/sysconfig/iptables
}

function port_forward(){
	echo ""
	echo "[*] IP Forwarding"
	echo "1" > /proc/sys/net/ipv4/ip_forward
	echo ""
	echo "************************ Completed Network Address Translation (NAT) **************************"
}

check_root
