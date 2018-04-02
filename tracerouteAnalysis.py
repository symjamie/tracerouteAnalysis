# Filename:  trace.py
# Author:  Yiming Sun (V00811496)
# Purpose:  CSc 361 - Assignment 3
# Date:  April 1st, 2018

import sys
import dpkt
import socket
import statistics


protos = set() # {(Protocol number, Protocol name)}.
sent = dict() # For Windows: {Sequence number : [(Timestamp, TTL), (Timestamp), (Timestamp), ...]},
              # for Linux: {(Source port, Destination port): [(Timestamp, TTL), (Timestamp), (Timestamp), ...]}.
nodes = dict() # {Intermediate destination node: Hop count (i.e. TTL of corresponding request)}.
frags = dict() # {ID: (Number of fragments, Largest offset in 8 bytes)}.
seqPort = dict() # For Windows: {ID: Sequence number}, for Linux: {ID: (Source port, Destination port)}.
rtts = dict() # {Node: [RTT]}.


def read(pcap):
	win = True # True: Windows trace, False: Linux trace.
	global srcNode, ultDst
	srcNode = ""

	# Some of the common IP protocol numbers.
	proto = {1: "ICMP", 2: "IGMP", 4: "IP", 6: "TCP", 8: "EGP", 9: "IGP", 17: "UDP", 46: "RSVP"}
	
	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)

		# Skip non-IP datagrams.
		if not isinstance(eth.data, dpkt.ip.IP):
			continue

		ip = eth.data

		# In following steps, only focus on traceroute-related (i.e. UDP and ICMP) datagrams.
		if not (ip.p == 17 or isinstance(ip.data, dpkt.icmp.ICMP)):
			continue

		# Record protocal name.
		protos.add((ip.p, proto[ip.p]))

		src = socket.inet_ntoa(ip.src)
		dst = socket.inet_ntoa(ip.dst)

		# Find the starting datagram of traceroute.
		if srcNode == "" and ip.ttl == 1:
			# Traceroute on Windows starts with an ICMP Echo request.
			if isinstance(ip.data, dpkt.icmp.ICMP):
				if ip.data.type == 8:
					srcNode = src
					ultDst = dst
			# Traceroute on Linux starts with an UDP datagram.
			else:
				win = False
				srcNode = src
				ultDst = dst

		if srcNode == "":
			continue

		# Analyze intermediate destination nodes, fragmentations and RTT values for windows trace.
		if win:
			# Check if this datagram is an ICMP datagram.
			if isinstance(ip.data, dpkt.icmp.ICMP):
				icmp = ip.data
				# This datagram is a forwarded ICMP Echo request.
				if icmp.type == 8:
					mf = bool(ip.off & dpkt.ip.IP_MF)
					fragOff = ip.off & dpkt.ip.IP_OFFMASK
					# This datagram is the first fragment.
					if mf and fragOff == 0:
						sent[icmp.data.seq] = [(ts, ip.ttl)]
						seqPort[ip.id] = icmp.data.seq
						frags[ip.id] = (1, 0)
					# This datagram is a following fragment.
					elif fragOff != 0:
						sent[seqPort[ip.id]].append((ts,))
						frags[ip.id] = (frags[ip.id][0] + 1, fragOff)
					# This datagram is not fragmented.
					else:
						sent[icmp.data.seq] = [(ts, ip.ttl)]
				# This datagram is a received ICMP response.
				elif dst == srcNode:
					# This datagram is an ICMP TTL Exceeded response from an intermediate destination node.
					if icmp.type == 11:
						echo = icmp.data.data.data.data
						nodes[src] = sent[echo.seq][0][1]
					# This datagram is an ICMP Echo Reply from the ultimate destination node.
					if icmp.type == 0:
						echo = icmp.data
					# Calculate RTTs based on all the corresponding fragments.
					if not src in rtts:
						rtts[src] = []
					for frag in sent[echo.seq]:
						rtts[src].append(ts - frag[0])

		# For Linux trace.
		else:
			# This datagram is a forwarded UDP datagram.
			if src == srcNode:
				mf = bool(ip.off & dpkt.ip.IP_MF)
				fragOff = ip.off & dpkt.ip.IP_OFFMASK
				# This datagram is the first fragment.
				if mf and fragOff == 0:
					sent[(ip.data.sport, ip.data.dport)] = [(ts, ip.ttl)]
					seqPort[ip.id] = (ip.data.sport, ip.data.dport)
					frags[ip.id] = (1, 0)
				# This datagram is a following fragment.
				elif fragOff != 0:
					sent[seqPort[ip.id]].append((ts,))
					frags[ip.id] = (frags[ip.id][0] + 1, fragOff)
				# This datagram is not fragmented.
				else:
					sent[(ip.data.sport, ip.data.dport)] = [(ts, ip.ttl)]
			# This datagram is a received ICMP response.
			elif isinstance(ip.data, dpkt.icmp.ICMP):
				icmp = ip.data
				udp = icmp.data.data.data
				# This datagram is an ICMP TTL Exceeded response from an intermediate destination node.
				if icmp.type == 11:
					nodes[src] = sent[(udp.sport, udp.dport)][0][1]
				# Calculate RTTs based on all the corresponding fragments.
				if not src in rtts:
					rtts[src] = []
				for frag in sent[(udp.sport, udp.dport)]:
					rtts[src].append(ts - frag[0])


def summary():
	print("The IP address of the source node: " + srcNode)
	print("The IP address of ultimate destination node: " + ultDst)
	print("The IP addresses of the intermediate destination nodes:")
	n = 1
	# Sort nodes by there corresponding TTLs.
	for node in sorted(((v,k) for k,v in nodes.items())):
		#print("\trouter " + str(n) + ": " + node[1] + " (hop count = " + str(node[0]) + ")")
		if n != len(nodes):
			print("\trouter " + str(n) + ": " + node[1] + ",")
		else:
			print("\trouter " + str(n) + ": " + node[1] + ".")
		n = n + 1
	print()
	print("The values in the protocol field of IP headers:")
	for (n, proto) in sorted(list(protos)):
		print("\t" + str(n) + ": " + proto)
	print()
	if frags:
		n = 1
		for ID, frag in frags.items():
			#print("\tID: " + str(ID))
			print("The number of fragments created from the original datagram D" + str(n) + " is: " + str(frag[0]))
			print("The offset of the last fragment is: " + str(frag[1]) + "\n")
			n = n + 1
	else:
		print("The number of fragments created from the original datagram is: 0")
		print("The offset of the last fragment is: 0\n")
	for node, rtt in rtts.items():
		if len(rtt) <= 1:
			print("The avg RTT between " + srcNode + " and " + node + " is: %.2f ms, the s.d. is: 0 ms" % (sum(rtt) * 1000))
		else:
			print("The avg RTT between " + srcNode + " and " + node + " is: %.2f ms, the s.d. is: %.2f ms" % (statistics.mean(rtt) * 1000, statistics.stdev(rtt) * 1000))


def main():
	if not len(sys.argv) == 2:
		print("ERROR: run the program with \"./tcp_traffic_analysis.py <filename>\".")
		sys.exit()

	try:
		f = open(sys.argv[1], "rb")
	except:
		print("ERROR: file \"" + sys.argv[1] + "\" does not exist.")
		sys.exit()

	try:
		pcap = dpkt.pcap.Reader(f)
	except:
		print("ERROR: file \"" + sys.argv[1] + "\" is not a valid pcap file.")
		sys.exit()

	read(pcap)
	summary()

	f.close()

if __name__ == '__main__':
    main()