#!/usr/bin/env python3

import binascii
import pytest
import sys
import time
from enum import IntEnum

from ledgerwallet.client import LedgerClient
from ledgerwallet.crypto.ecc import PrivateKey
from ledgerwallet.params import Bip32Path
from ledgerwallet.transport import enumerate_devices

DEFAULT_PATH = "44'/535348'/0'/0/0"
CLA = 0x80

class Ins(IntEnum):
    GET_PUBLIC_KEY    = 0x02
    SIGN_SSH_BLOB     = 0x04
    SIGN_GENERIC_HASH = 0x06
    SIGN_DIRECT_HASH  = 0x08
    GET_ECDH_SECRET   = 0x0A

class P1(IntEnum):
    FIRST             = 0x00
    NEXT              = 0x01
    LAST_MARKER       = 0x80
    LAST              = 0x81

class Curve(IntEnum):
    PRIME256          = 0x01
    CURVE25519        = 0x02
    INVALID_03        = 0x03
    PUBLIC_KEY_MARKER = 0x80

def build_apdu(ins, payload, p1, curve):
    data = CLA.to_bytes(1, "big")
    data += ins.to_bytes(1, "big")
    data += p1.to_bytes(1, "big")
    data += curve.to_bytes(1, "big")
    data += len(payload).to_bytes(1, "big")
    data += payload
    return data

@pytest.fixture(scope="module")
def client():
    devices = enumerate_devices()
    if len(devices) == 0:
        print("No Ledger device has been found.")
        sys.exit(0)

    return LedgerClient(devices[0])

class Client:
    def apdu_exchange(self, client, payload=b"", p1=P1.FIRST, curve=Curve.PRIME256):
        apdu = build_apdu(self.INS, payload, p1, curve)
        response = client.raw_exchange(apdu)
        # some hangs were noticed with speculos otherwise
        time.sleep(0.2)
        status_word = int.from_bytes(response[-2:], "big")
        return status_word, response[:-2]

class TestGetPublicKey(Client):
    INS = Ins.GET_PUBLIC_KEY

    def test_get_public_key(self, client):
        path = Bip32Path.build(DEFAULT_PATH)
        status_word, _ = self.apdu_exchange(client, path)
        assert status_word == 0x9000

    def test_path_too_long(self, client):
        path = Bip32Path.build(DEFAULT_PATH + "/0/0/0/0/0/0")
        status_word, _ = self.apdu_exchange(client, path)
        assert status_word == 0x6a80

class TestSignGenericHash(Client):
    INS = Ins.SIGN_GENERIC_HASH

    def test_sign_generic_hash(self, client):
        payload = Bip32Path.build(DEFAULT_PATH) + b"a"
        status_word, _ = self.apdu_exchange(client, payload)
        assert status_word == 0x9000

        status_word, _ = self.apdu_exchange(client, b"b", p1=P1.NEXT)
        assert status_word == 0x9000

        status_word, _ = self.apdu_exchange(client, b"b", p1=P1.LAST)
        assert status_word == 0x9000

    def test_invalid_curve(self, client):
        status_word, _ = self.apdu_exchange(client, curve=Curve.INVALID_03)
        assert status_word == 0x6b00

class TestSignDirectHash(Client):
    INS = Ins.SIGN_DIRECT_HASH

    def test_sign_direct_hash(self, client):
        payload = Bip32Path.build(DEFAULT_PATH) + b"a" * 32
        status_word, _ = self.apdu_exchange(client, payload)
        assert status_word == 0x9000

    def test_invalid_hash_len(self, client):
        payload = Bip32Path.build(DEFAULT_PATH) + b"a"
        status_word, _ = self.apdu_exchange(client, payload)
        assert status_word == 0x6700

    def test_invalid_steps(self, client):
        status_word, _ = self.apdu_exchange(client, p1=P1.NEXT)
        assert status_word == 0x6b00

        status_word, _ = self.apdu_exchange(client, p1=P1.LAST)
        assert status_word == 0x6b00

class TestGetECDHSecret(Client):
    INS = Ins.GET_ECDH_SECRET

    def test_get_ecdh_secret(self, client):
        pubkey = PrivateKey().pubkey.serialize(compressed=False)
        payload = Bip32Path.build(DEFAULT_PATH) + pubkey
        status_word, _ = self.apdu_exchange(client, payload)
        assert status_word == 0x9000

class TestSignSSHBlob(Client):
    INS = Ins.SIGN_SSH_BLOB

    def test_sign_ssh_blob(self, client):
        requests = [ b"0\x00", b"username", b"22", b"333\x00", b"4444", b"55555" ]
        payload = Bip32Path.build(DEFAULT_PATH)
        for i, request in enumerate(requests):
            length = len(request)
            if i == 0 or i == 3:
                length -= 1
            payload += length.to_bytes(4, "big")
            payload += request

        status_word, data = self.apdu_exchange(client, payload)
        assert status_word == 0x9000
        assert data.startswith(b"\x30")
