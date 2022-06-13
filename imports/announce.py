from .sum import Sum
import sys
import time
import struct

class Announce:
	def __init__(self, ip, info_hash, peer_id, port, uploaded, downloaded, left, compact, no_peer_id, event, key):
		self.info_hash = info_hash
		self.peer_id = peer_id
		self.port = port
		self.uploaded = uploaded
		self.downloaded = downloaded
		self.left = left
		self.compact = compact
		self.no_peer_id = no_peer_id
		self.event = event
		self.key = key
		self.ip = ip
		self.sum = Sum(ip, port, peer_id, key, info_hash)
	def validateInput(self, input, sha1hash=False, needed=False):
		if input == None and needed == True:
			return False
		if input == None and needed == False:
			return True
		if sha1hash:
			if len(input) != 20:
				return False
		if len(input) > 128:
			return False
		return True
	def formaResponseCompact(self, database):
		resp = b'd8:intervali120e10:tracker id4:test'
		c = 0
		i = 0
		for k in database:
			if database[k][4] == self.info_hash:		# count Complete and Incomplete downloads
				if database[k][5] == True:
					c += 1
				else:
					i += 1
		resp += b'8:completei' + str(c).encode("utf-8") + b'e10:incompletei' + str(i).encode("utf-8") + b'e5:peers'

		peers_f = 0
		for k in database:
			if database[k][4] == self.info_hash and k != self.sum.sum:	# count num of peers to send str length
				peers_f += 1
				resp += str(6*peers_f).encode("utf-8") + b':'

		for k in database:
			if database[k][4] == self.info_hash and k != self.sum.sum:

					# Split ip, convert them to int, convert to raw bytes, convert port to raw bytes too
					nums = database[k][0].split('.')

					for n in range(len(nums)):
						nums[n] = struct.pack('!B', int(nums[n]))

					conv_port = struct.pack("!H", int(database[k][1]))

					resp += b''.join(nums) + conv_port
		resp += b'e'
		return resp

	def formatResponse(self, database):
		resp = 'd8:intervali120e10:tracker id4:test'
		c = 0
		i = 0
		for k in database:
			if database[k][4] == self.info_hash:		# count Complete and Incomplete downloads
				if database[k][5] == True:
					c += 1
				else:
					i += 1
		resp += '8:completei' + str(c) + 'e10:incompletei' + str(i) + 'e5:peersl'

		for k in database:
			if database[k][4] == self.info_hash and k != self.sum.sum:
					resp += 'd2:ip' + str(len(database[k][0])) + ':' + database[k][0] + '4:porti' + database[k][1] + 'ee'


		resp += 'ee'
		return resp


	def handle(self, database):
		errormsg = "Error"
		if self.validateInput(self.info_hash, False, True) == False: return errormsg+'0'
		if self.validateInput(self.peer_id, True, True) == False: return errormsg+'1'
		if self.validateInput(self.port, False, True) == False: return errormsg+'2'
		if self.validateInput(self.uploaded, False, True) == False: return errormsg+'3'
		if self.validateInput(self.downloaded, False, True) == False: return errormsg+'4'
		if self.validateInput(self.left, False, True) == False: return errormsg+'5'
		if self.validateInput(self.compact) == False: return errormsg+'6'
		if self.validateInput(self.no_peer_id) == False: return errormsg+'7'
		if self.validateInput(self.event) == False: return errormsg+'8'
		if self.validateInput(self.key) == False: return errormsg+'9'

		if self.sum.sum in database:
			if self.key != database[self.sum.sum][3]:
				return "Access Denied!"


		recv_time = time.time()
		if self.sum.sum in database:
			if recv_time - database[self.sum.sum][6] < 120:		# Check if time is 120 between requests
				#return "E:Wait..."
				pass

		database[self.sum.sum] = self.sum.getArray()

		if int(self.left) == 0:
			database[self.sum.sum][5] = True		# set seeding to true

		if self.event == "stopped":
			del database[self.sum.sum]

		for k in database:
			if time.time() - database[k][6] > 120*3:		# delete records if timed out
				del database[k]

		if self.compact == '1':
			resp = self.formaResponseCompact(database)
		else:
			resp = self.formatResponse(database)
		return resp


