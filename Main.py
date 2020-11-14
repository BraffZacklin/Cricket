#!/bin/python3

def main():
	# Set up logging and arguments
	import logging
	import sys
	import argparse

	parser = argparse.ArgumentParser(description='A program that hops 2.4GHz channels to detect beacon frames and de-authorises all wirelessly connected hosts on the AP; Authentication frames may also be captured and saved to a .pcap file specified')
	ignoring = parser.add_mutually_exclusive_group()
	verbosity = parser.add_mutually_exclusive_group()
	attacks = parser.add_mutually_exclusive_group()

	parser.add_argument('int1', action='store', help='Sets the interface to use for sending and/or receiving')
	parser.add_argument('int2', nargs='?', action='store', help='Sets a secondary interface to use; int1 sends, int2 receives', default=None)

	ignoring.add_argument('-l', '--ignore-list', dest='list', action='store', type=list, help='Ignore APs given by command line input (by ESSID or BSSID, separated by spaces)')
	ignoring.add_argument('-f', '--ignore-file', dest='file', action='store', type=str, help='Ignore APs from this file (by ESSID or BSSID, separated by newlines)')

	attacks.add_argument('-t', '--target', dest='target', action='store', type=list, help='Target one or more APs (by ESSID or BSSID)')
	attacks.add_argument('-s', '--spray', dest='spray', action='store_const', const='spray', help='Target every discovered AP until a handshake is captured')
	attacks.add_argument('-u', '--unarmed', dest='unarmed', action='store_const', const='unarmed', help='Do not send any de-auth frames')
	
	verbosity.add_argument('-vv', '--very-verbose', dest='verbosity', action='store_const', const=logging.DEBUG, help='Set program to log debug information')
	verbosity.add_argument('-v', '--verbose', dest='verbosity', action='store_const', const=logging.INFO, help='Set program to log normal functioning')

	parser.add_argument('-o', '--output', dest='output', action='store', type=str, help='File to write captured Auth Frames to (will only jam if not set)')
	parser.add_argument('-c', '--channel', dest='channels', action='store', type=list, help='Channels to hop on (default is 1-11)', default=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])

	args = parser.parse_args()
	logging.basicConfig(stream=sys.stdout, format='\t%(message)s',level=args.verbosity)
	
	# Import Cricket instance
	from Cricket import Cricket

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
		targets = args.target
	elif args.spray:
		attackMode = 'spray'
	elif args.unarmed:
		attackMode = 'unarmed'

	# Set appropriate sending and receiving interfaces
	int1 = args.int1

	if not args.int2:
		int2 = args.int1
	else:
		int2 = args.int2

	# Create Cricket instance and run
	cricket = Cricket(ignoredAPs, attackMode, int1, int2, args.output, args.channels, targets=targets)

	# Need to figure out a way to have multiple threads

	# Except Ctrl + C to close everything
	except KeyboardInterrupt:

		statistics = {}
		wapsDiscovered = 0
		handshakesFound = 0
		for AccessPoint in cricket.discoveredAPs:
			wapsDiscovered += 1

			# if a dict entry exists, append to it's corresponding list, else create it
			if statistics[AccessPoint.channel]:
				statistics[AccessPoint.channel].append(AccessPoint)
			else:
				statistics[AccessPoint.channel] = [AccessPoint]

		for channels in statistics:
			for AccessPoint in statistics[channel]:
				if AccessPoint.bssid in cricket.handshakesFound:
					handshakesFound += 1
					log_str = '<Handshake Found>\t\t'		
				else:
					log_str = '<Handshake Not Found>\t'
				log_str += 'ESSID: ' + AccessPoint.essid + ' CH: ' + str(AccessPoint.essid)
				logging.info(log_str)
		logging.info('\tWireless Access Points Discovered:\t' + str(wapsDiscovered))
		logging.info('\tWPA2 Handshakes Captured:\t\t' + str(handshakesFound))
		quit()

if __name__ == '__main__':
    main()