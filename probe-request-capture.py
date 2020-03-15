import scapy.all
from datetime import datetime
import sqlite3
import threading, time, os
import requests

dbfile = '/root/Desktop/data.db' # path to SQLite3 file
wigleAPIName = '' # Wigle API Name from https://wigle.net/account
wigleAPIToken = '' # Wigle API token from https://wigle.net/account
ssidLocation = [] # previously found locations for SSIDs
ifaceName = "wlan0mon" # interface in monitor mode

class channelHopper(threading.Thread):
	def __init__(self, minChannel, maxChannel, hopFreq):
		threading.Thread.__init__(self)
		self.minChannel = minChannel
		self.maxChannel = maxChannel
		self.curChannel = self.minChannel
		self.hopFreq = hopFreq # frequency of channel hopping in seconds

	def setChannel(self, channel):
			command = 'iwconfig wlan0mon channel ' + str(channel)
			os.system(command)

	def run(self):
		# set initial channel to minimum in range
		self.setChannel(self.minChannel)
		
		while 1:
			# change channel
			self.setChannel(self.curChannel)

			time.sleep(self.hopFreq) # sleep to give time for capture on the channel

			if self.curChannel < self.maxChannel: # increments channel within the allowed range
				self.curChannel += 1
			else: # resets channel to start of range if we're out of range or in unexpected range
				self.curChannel = self.minChannel

# use Wigle API to lookup SSID lat,long
# only return result if a single location is found
def getSSIDLocation(ssid):
	# return SSID from is previously found and saved in ssidLocation list
	for entry in ssidLocation:
		if entry['SSID'] == ssid:
			return entry['Location']

	# SSID not previously seen, now looking up with API
	url = 'https://api.wigle.net/api/v2/network/search?onlymine=false&first=0&freenet=false&paynet=false&ssid=%s' % (ssid)
	response = requests.get(url = url, auth=(wigleAPIName, wigleAPIToken))

	if response.status_code == 200: # if API call is successful
		json = response.json() # decode JSON response

		# If JSON response contains an error message
		if json['success'] == False:
			print('Wigle API lookup failed with message: %s' % (json['message']))
			return None

		# If a single location is found for the SSID
		if json['resultCount'] == 1:
			# string of SSID lat,long
			location = '%s, %s' % (json['results'][0]['trilat'], json['results'][0]['trilong'])

		# If multiple locations are found for the SSID or unexpected result
		else:
			location = None

		# add entry to list of already searched SSID's to reduce numer of API calls and make processing faster
		entry = {'SSID': ssid, 'Location': location}
		ssidLocation.append(entry)

		return location
	else:
		print('API lookup failed status code: %s. Reason: %s ' % (response.status_code, response.content.decode("utf-8")))
		return None

def getPacketSSID(pkt):
	try:
		ssid = pkt.info.decode("utf-8") # get SSID in UTF-8
	except:
		print("Failed to decode SSID, saving as raw bytes:" % (pkt.info))
		ssid = pkt.info

	return ssid

def getPacketTimestamp(pkt):
	timestamp = str(pkt.time).split('.')[0] # save UNIX time from packet
	timestamp = datetime.utcfromtimestamp(int(timestamp)) # convert UNIX time string to datetime
	return timestamp

# called when a packet 'pkt' is captured
def print_callback(pkt):
	if pkt.type == 0 and pkt.subtype == 4: # management type && probe request

		macfilter = ''.upper() # filter for a specific source MAC address or part of a source MAC address
		mac = pkt.addr2.upper() # source MAC address from probe request packet

		if macfilter and mac.find(macfilter) == -1: # if filter is set, and the packet source is not MAC we filter for
			return
		else: # packet is valid
			mac_prefix = mac[:8] # anonymize source MAC address

			timestamp = getPacketTimestamp(pkt) # get datetime timestamp from packet

			# get current wlan frequency
			frequency = pkt.ChannelFrequency
			
			ssid = getPacketSSID(pkt) # get SSID from packet

			# Change wildcard SSID probe requests from empty string to 'Wildcard'
			if ssid == '':
				ssid = 'Wildcard'
				location = None
			else:
				location = getSSIDLocation(ssid)
				locationOut = location

			# format location string to look nice in CLI output
			if location == None:
				locationOut = "None                    "

			# save probe request to db
			conn.execute('INSERT INTO probes (timestamp, mac_prefix, frequency, location, ssid) VALUES (?,?,?,?,?)', (timestamp, mac_prefix, frequency, location, ssid))
			conn.commit()

			# output to command line
			print("%s | %s   | %s      | %s | %s" % (timestamp, mac_prefix, frequency, locationOut, ssid))

thread = channelHopper(1, 13, 0.25) # create thread for hopping wifi channels
thread.start() # start hopping channels

conn = sqlite3.connect(dbfile) # open DB connection

# create probe table if it doesn't exist
conn.execute('create table if not exists probes (timestamp NUMERIC, mac_prefix TEXT, frequency NUMERIC, location TEXT, ssid TEXT);')
conn.commit()

print("Timestamp           | MAC prefix | Frequency | Location                 | SSID") # print CLI header
scapy.all.sniff(iface=ifaceName, count=0, prn=print_callback, store=0) # start sniffing
conn.close() # close DB connection