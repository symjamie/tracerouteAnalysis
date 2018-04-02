# tracerouteAnalysis
Author:  Yiming Sun

Purpose:  CSc 361 - Assignment 2

Date:  Feb 24, 2018

--------------------------------------------------------------------------

Excecution environment:

	Python 3.6 with dpkt module.

--------------------------------------------------------------------------

Input:

	A valid .pcap file in the argument line. (e.g. run the program with
	"./python3 trace.py trace1.pcap").

--------------------------------------------------------------------------

Output:

	1. The IP address of the source node;

	2. The IP address of ultimate destination node;

	3. The IP addresses of the intermediate destination nodes;

	4. The values in the protocol field of IP headers:

	5. The number of fragments created from the original datagram, and the
	   offset of the last fragment;

	6. The average RTT between the source node and all the destination nodes.

--------------------------------------------------------------------------

Error handlings:

	1. Output an error message if the filename is not provided properly;

	2. Output an error message if the file can not be opened;

	3. Output an error message if the file can not be read as a pcap file.

--------------------------------------------------------------------------

Details about implementations are commented in source code.
