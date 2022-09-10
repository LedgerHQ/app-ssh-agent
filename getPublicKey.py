#!/usr/bin/env python
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
import codecs

KEY_HEADER = "ecdsa-sha2-nistp256"
CURVE_NAME = "nistp256"
KEY_HEADER_ED25519 = "ssh-ed25519"

def parse_bip32_path(path):
	if len(path) == 0:
		return ""
	result = b""
	elements = path.split('/')
	for pathElement in elements:
		element = pathElement.split('\'')
		if len(element) == 1:
			result = result + struct.pack(">I", int(element[0]))			
		else:
			result = result + struct.pack(">I", 0x80000000 | int(element[0]))
	return result

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to retrieve")
parser.add_argument("--ed25519", help="Use Ed25519 curve", action='store_true')
args = parser.parse_args()

if args.path == None:
	args.path = "44'/535348'/0'/0/0"

if args.ed25519:
	p2 = "02"
	keyHeader = KEY_HEADER_ED25519
else:
	p2 = "01" 
	keyHeader = KEY_HEADER

donglePath = parse_bip32_path(args.path)
apdu = "800200" + p2 
#apdu = apdu.decode('hex') + chr(len(donglePath) + 1) + chr(len(donglePath) / 4) + donglePath
apdu = codecs.decode(apdu, 'hex') + bytes(chr(len(donglePath) + 1), encoding='utf8') + bytes(chr(int(len(donglePath) / 4)), encoding='utf8') + donglePath
dongle = getDongle(True)
result = dongle.exchange(bytes(apdu))
key = str(result[1:])
blob = struct.pack(">I", len(KEY_HEADER)) + bytes(keyHeader, encoding="utf-8") 
if args.ed25519:
	keyX = bytearray(key[0:32])
	keyY = bytearray(key[32:][::-1])
	if ((keyX[31] & 1) != 0):
		keyY[31] |= 0x80
	key = str(keyY)
else:
	blob += struct.pack(">I", len(CURVE_NAME)) + bytes(CURVE_NAME, encoding="utf-8") 
	
blob += struct.pack(">I", len(key)) + bytes(key, encoding="utf-8")
print(keyHeader + " " + base64.b64encode(blob).decode("utf-8"))

