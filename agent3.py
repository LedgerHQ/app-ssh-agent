"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct
import base64
import os 
import socket
import tempfile
import threading
import logging
import binascii

SIG_HEADER = b"ecdsa-sha2-nistp256"
SIG_HEADER_EDDSA = b"ssh-ed25519"

SOCK_PREFIX = 'blue-ssh-agent'
TIMEOUT = 0.5

SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENTC_SIGN_REQUEST = 13

SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENT_SIGN_RESPONSE = 14

SSH_AGENT_FAILURE = 5

DEPTH_REQUEST_1 = 0
DEPTH_REQUEST_2 = 3

def _is_valid_challenge_format(data):
	"""Checks if data is a valid format that can be parsed by ledger devices"""
	offset = 0
	depth = 0
	while offset < len(data):
		"""Read length"""
		length = struct.unpack_from(">I", data, offset)[0]
		if depth == DEPTH_REQUEST_1 or depth == DEPTH_REQUEST_2:
			length += 1
		offset += 4 + length
		depth += 1
	return offset == len(data)

def handleRequestIdentities(message, key, eddsa, path):
	logging.debug("Request identities")
	response = struct.pack("B", SSH2_AGENT_IDENTITIES_ANSWER)
	response += struct.pack(">I", 1)
	response += struct.pack(">I", len(key)) + key
	response += struct.pack(">I", len(path)) + path.encode()
	return response

def handleSignRequest(message, key, eddsa, path):
	logging.debug("Sign request")
	blobSize = struct.unpack(">I", message[0:4])[0]
	blob = message[4 : 4 + blobSize]
	if blob != key:
		logging.debug("Client sent a different blob " + binascii.hexlify(blob).decode())
		return struct.pack("B", SSH_AGENT_FAILURE)
	challengeSize = struct.unpack(">I", message[4 + blobSize : 4 + blobSize + 4])[0]
	challenge = message[4 + blobSize + 4: 4 + blobSize + 4 + challengeSize]
	valid_challenge_format = _is_valid_challenge_format(blob)
	
	dongle = getDongle(logging.getLogger().isEnabledFor(logging.DEBUG))
	donglePath = parse_bip32_path(path)
	offset = 0
	while offset != len(challenge):
		data = b""
		if offset == 0:
			donglePath = parse_bip32_path(path)
			data = struct.pack("B", len(donglePath) // 4) + donglePath
		chunkSize = min(255 - len(data), len(challenge) - offset)
		data += challenge[offset : offset + chunkSize]
		p1 = 0x00 if offset == 0 else 0x01
		p2 = 0x02 if eddsa else 0x01
		offset += chunkSize
		if offset == len(challenge):
			p1 |= 0x80
		ins = "04" if valid_challenge_format else "06"
		apdu = binascii.unhexlify("80" + ins) + struct.pack("B", p1) + struct.pack("B", p2) + struct.pack("B", len(data)) + data
		signature = dongle.exchange(apdu)
	dongle.close()

	rLength = signature[3]
	r = signature[4 : 4 + rLength]
	sLength = signature[4 + rLength + 1]
	s = signature[4 + rLength + 2:]

	encodedSignatureValue = struct.pack(">I", len(r)) + r
	encodedSignatureValue += struct.pack(">I", len(s)) + s

	encodedSignature = struct.pack(">I", len(SIG_HEADER)) + SIG_HEADER
	encodedSignature += struct.pack(">I", len(encodedSignatureValue)) + encodedSignatureValue

	response = struct.pack("B", SSH2_AGENT_SIGN_RESPONSE)
	response += struct.pack(">I", len(encodedSignature)) + encodedSignature
	return response

def clientHandlerInternal(connection, key, eddsa, comment):
	logging.debug("Handling new client")
	while True:		
		try:
			header = connection.recv(4)
		except socket.timeout:
			logging.debug("Timeout")
			header = b""
		if len(header) == 0:
			logging.debug("Client dropped connection")
			break
		size = struct.unpack(">I", header)[0]
		try:
			message = connection.recv(size)
		except socket.timeout:
			logging.debug("Timeout")
			message = b""
		if len(message) == 0:
			logging.debug("Client dropped connection")
			break
		logging.debug("<= " + binascii.hexlify(message).decode())
		messageType = message[0]
		if messageType == SSH2_AGENTC_REQUEST_IDENTITIES:
			response = handleRequestIdentities(message[1:], key, eddsa, comment)
		elif messageType == SSH2_AGENTC_SIGN_REQUEST:
			response = handleSignRequest(message[1:], key, eddsa, comment)
		else:
			logging.debug("Unhandled message")
			response = struct.pack("B", SSH_AGENT_FAILURE)
		agentResponse = struct.pack(">I", len(response)) + response
		logging.debug("=> " + binascii.hexlify(agentResponse).decode())
		connection.send(agentResponse)

def clientHandler(connection, key, eddsa, comment):		
	try:
		clientHandlerInternal(connection, key, eddsa, comment)
	except Exception:
		logging.debug("Internal error handling client", exc_info=True)
		response = struct.pack("B", SSH_AGENT_FAILURE)
		agentResponse = struct.pack(">I", len(response)) + response
		logging.debug("=> " + binascii.hexlify(agentResponse).decode())
		connection.send(agentResponse)

def parse_bip32_path(path):
	if len(path) == 0:
		return b""
	result = b""
	elements = path.split('/')
	for pathElement in elements:
		element = pathElement.split('\'')
		if len(element) == 1:
			result += struct.pack(">I", int(element[0]))			
		else:
			result += struct.pack(">I", 0x80000000 | int(element[0]))
	return result

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to use")
parser.add_argument('--key', help="SSH encoded key to use")
parser.add_argument("--ed25519", help="Use Ed25519 curve", action='store_true')
parser.add_argument('--debug', help="Display debugging information", action='store_true')
args = parser.parse_args()

if args.path is None:
	args.path = "44'/535348'/0'/0/0"

if args.key is None:
	raise Exception("No key specified")

if args.debug:
	logging.basicConfig(level=logging.DEBUG)

keyBlob = base64.b64decode(args.key)

socketPath = tempfile.NamedTemporaryFile(prefix=SOCK_PREFIX, delete=False)
os.unlink(socketPath.name)
print("Export those variables in your shell to use this agent")
print("export SSH_AUTH_SOCK=" + socketPath.name)
print("export SSH_AGENT_PID=" + str(os.getpid()))
print("Agent running ...")

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socketPath.name)
server.listen(1)
try:
	while True:
		logging.debug("Server waiting ...")
		connection, addr = server.accept()
		logging.debug("New client connected")
		connection.settimeout(TIMEOUT)
		threading.Thread(target=clientHandler, args=(connection, keyBlob, args.ed25519, args.path)).start()
except KeyboardInterrupt:
	pass
finally:
	os.unlink(socketPath.name)
