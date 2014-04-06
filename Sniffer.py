#!/usr/bin/python

import socket
import struct
import binascii
import time

logo = """
################################################################################
# sniffer.py -- Python Sniffer v1.1                                            #
#                                                                              #
# DATE                                                                         #
# 05/04/2014                                                                   #
#                                                                              #
# DESCRIPTION                                                                  #
# Python Sniffer                                                               #
#                                                                              #
# AUTHOR                                                                       #
# darknight10011 [at] gmail [dot] com                                          #
# 			                                                       #
#                                                                              #
################################################################################    



          [--]          Sniffer v1.1 - Python Raw Socket Based Sniffer		[--] 
          [--]                   Written By: D4rk     	          		[--]
          [--]               http://www.highhacksociety.com           		[--]

"""

print logo
time.sleep (2)

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

#Starting Counter
icmp=0
tcp=0
udp=0
other=0

#Working for Ethernet Header
def ethernetHeader(pkts):
	
	#Unpacking Ethernet header
	ethheader = pkts[0][0:14]
        eth_header = struct.unpack("!6s6s2s", ethheader)
        destmac = binascii.hexlify(eth_header[0])
        srcmac = binascii.hexlify(eth_header[1])
	tag = "\r\n"
	return 'DestinationMac: ' +  destmac.strip() + ' SourceMac: ' +  srcmac.strip() + tag


#Extracting ECN from TCP Header

def getEcn(pkts):
        N = "NS"
        C = "CWR"
        E = "ECE"

        NS = pkts & 0x100
        NS >>= 8
        CWR = pkts & 0x80
        CWR >>= 7
        ECE = pkts & 0x40
        ECE >>= 6

        tabs = ","
        ecpli = N[NS] + tabs + C[CWR] + tabs + E[ECE]
        return ecpli


def getflags(pkts): 
	U = {0: '0', 1: '1'}
	A = {0: '0', 1: '1'}
        P = {0: '0', 1: '1'}
        R = {0: '0', 1: '1'}
        S = {0: '0', 1: '1'}
        F = {0: '0', 1: '1'}

        UR = pkts & 0x20
        UR >>=5
        AC = pkts & 0x10
        AC >>=4
        PS = pkts & 0x8
        PS >>=3
        RS = pkts & 0x4
        RS>>=2
        SY = pkts & 0x2
        SY>>=1
        FI = pkts & 0x1
        tabs = ","
        final = U[UR] + tabs + A[AC] + tabs + P[PS] + tabs + R[RS] + tabs + S[SY] + tabs + F[FI]
        return final


#Checking Ports

def chk_ports(sport):
	list_ports = {22: 'SSH', 80: 'HTTP', 23: 'Telnet', 21: 'FTP', 25: 'SMTP', 53: 'DNS', 3308: 'Mysql', 3389: 'RDP', 5222: 'XMPP-client', 8001: 'VCOM-Tunnel'}
	try:
	 	list_ports[sport]
		return list_ports[sport]
	except KeyError:
		return "No Service"


def ipheader(pkts):
	0
	#Unpacking Ip header
	#total_length, protocol, ttl

	ipheader = pkts[0][14:34]
	ip_header = struct.unpack("!BBHHHBBH4s4s", ipheader)
	version_head = ip_header[0]
	version = version_head >> 4 #Version Extracted 
	ihl = version_head & 0xF
	iph_length = ihl * 4        # IHL Extracted
	protocol = ip_header[6]
	saddr = socket.inet_ntoa(ip_header[8])
	daddr = socket.inet_ntoa(ip_header[9])
	total_length = ip_header[2]	
	ttl = ip_header[5]
	tag = "\r\n"
	return 'Version=' + str(version) + tag + 'IpHeaderLength=' + str(iph_length) + ' Protocol=' + str(protocol) + tag + 'SRCAddr=' + str(saddr) + ' DSTAddr=' + str(daddr) + ' TTL='+ str(ttl) + tag


def tcpheader(pkts):
	
	#Unpacking TCP Header
	tcpHeader = pkts[0][34:54]
	tcp_Header = struct.unpack("!HHLLBBHHH", tcpHeader)
	sport = tcp_Header[0]
	dport = tcp_Header[1]
	urg_pointer = tcp_Header[8]
	sequence = tcp_Header[2]
	ack = tcp_Header[3]
	doff_reserved = tcp_Header[4]
	tcph_length = doff_reserved >> 4
	ecn = tcp_Header[5]
	controlbit = tcp_Header[5] & 0x3F
	tag = "\r\n"

	return 'SRCport=' + str(sport) + ' DSTport=' + str(dport) + tag

def flush():
	flush_file = open("capture.txt", "w")
	flush_file.close()
flush()



while True:
	pkts = rawSocket.recvfrom(65535)
	tag = "\r\n"
	tag_end = "______________________________________________"
	timestmp = time.strftime("%H:%M:%S %d/%m/%Y")
	capture = timestmp + " " + str(ethernetHeader(pkts)) + str(ipheader(pkts)) + str(tcpheader(pkts)) + tag + tag_end + tag

#Dumping into Text	
	fdesc = open("capture.txt", "a")
	fdesc.write(str(capture) + "\n")

	pkt = rawSocket.recvfrom(65535)
        ipHeader = pkt[0][14:34]
        ip_header = struct.unpack("!BBHHHBBH4s4s", ipHeader)
        proto = ip_header[6]
        if proto==1:
                icmp += 1
        elif proto==6:
                tcp += 1
        elif proto==17:
                udp += 1
        else:
                other += 1
	tag = ','
	print "ICMP[%d]"%icmp + " TCP[%d]"%tcp + " UDP[%d]"%udp + " OTHER[%d]"%other
else:
	print "Empty Set"


