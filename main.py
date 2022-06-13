# Define flask /announce section
# there call announce(args) from diferent file
# main will have the list of 'sum' classes (data from the user and the actula download. id: sha1(user_id+info_hash))
# sum class has: id, ip, port, key, peer_id, info_hash, isseeding
# announce.py will handle the datas, validate, handle database, respond

from flask import Flask
from flask import request
from imports.announce import Announce
from urllib.parse import unquote
import sys

app = Flask("BitTracker")
database = {}

@app.route("/announce", methods=['GET'])
def announce():
	global database
	print(unquote(request.args.get("info_hash")), " ", len(unquote(request.args.get("info_hash"))), file=sys.stderr)
	an = Announce(request.remote_addr, unquote(request.args.get("info_hash")), request.args.get("peer_id"), request.args.get("port"), request.args.get("uploaded"), request.args.get("downloaded"), request.args.get("left"), request.args.get("compact"), request.args.get("no_peer_id"), request.args.get("event"), request.args.get("key"))
	resp = an.handle(database)
	return resp
	
if __name__ == "__main__":
	app.run(host="0.0.0.0", use_debugger=False, use_reloader=False, passthrough_errors=True)