from hashlib import sha1
import time

class Sum:
	def __init__(self, ip, port, pid, key, info_hash):
		self.sum = sha1((pid+info_hash).encode("utf-8")).digest()
		self.ip = ip
		self.port = port
		self.pid = pid
		self.key = key
		self.info_hash = info_hash
	def getArray(self):
		return [self.ip, self.port, self.pid, self.key, self.info_hash, False, time.time()]	# Last false is isseeding()