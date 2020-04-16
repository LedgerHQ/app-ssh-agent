#!/usr/bin/env python3

import binascii
import pytest
import sys
import time
from enum import IntEnum

from ledgerwallet.client import LedgerClient, CommException
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

@pytest.fixture(scope="module")
def client():
    devices = enumerate_devices()
    if len(devices) == 0:
        print("No Ledger device has been found.")
        sys.exit(0)

    return LedgerClient(devices[0], cla=CLA)

class TestGetPublicKey:
    INS = Ins.GET_PUBLIC_KEY

    def test_get_public_key(self, client):
        path = Bip32Path.build(DEFAULT_PATH)
        client.apdu_exchange(self.INS, path, P1.FIRST, Curve.PRIME256)

    def test_path_too_long(self, client):
        path = Bip32Path.build(DEFAULT_PATH + "/0/0/0/0/0/0")
        with pytest.raises(CommException) as e:
            client.apdu_exchange(self.INS, path, P1.FIRST, Curve.PRIME256)
        assert e.value.sw == 0x6a80

class TestSignGenericHash:
    INS = Ins.SIGN_GENERIC_HASH

    def test_sign_generic_hash(self, client):
        payload = Bip32Path.build(DEFAULT_PATH) + b"a"
        client.apdu_exchange(self.INS, payload, P1.FIRST, Curve.PRIME256)
        client.apdu_exchange(self.INS, b"b", P1.NEXT, Curve.PRIME256)
        client.apdu_exchange(self.INS, b"b", P1.LAST, Curve.PRIME256)

    def test_invalid_curve(self, client):
        with pytest.raises(CommException) as e:
            client.apdu_exchange(self.INS, sw1=P1.FIRST, sw2=Curve.INVALID_03)
        assert e.value.sw == 0x6b00

class TestSignDirectHash:
    INS = Ins.SIGN_DIRECT_HASH

    def test_sign_direct_hash(self, client):
        payload = Bip32Path.build(DEFAULT_PATH) + b"a" * 32
        client.apdu_exchange(self.INS, payload, P1.FIRST, Curve.PRIME256)

    def test_invalid_hash_len(self, client):
        payload = Bip32Path.build(DEFAULT_PATH) + b"a"
        with pytest.raises(CommException) as e:
            client.apdu_exchange(self.INS, payload, sw1=P1.FIRST, sw2=Curve.PRIME256)
        assert e.value.sw == 0x6700

    def test_invalid_steps(self, client):
        with pytest.raises(CommException) as e:
            client.apdu_exchange(self.INS, sw1=P1.NEXT, sw2=Curve.PRIME256)
        assert e.value.sw == 0x6b00

        with pytest.raises(CommException) as e:
            client.apdu_exchange(self.INS, sw1=P1.LAST, sw2=Curve.PRIME256)
        assert e.value.sw == 0x6b00

class TestGetECDHSecret:
    INS = Ins.GET_ECDH_SECRET

    def test_get_ecdh_secret(self, client):
        pubkey = PrivateKey().pubkey.serialize(compressed=False)
        payload = Bip32Path.build(DEFAULT_PATH) + pubkey
        client.apdu_exchange(self.INS, payload, sw1=P1.FIRST, sw2=Curve.PRIME256)

class TestSignSSHBlob:
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

        data = client.apdu_exchange(self.INS, payload, sw1=P1.FIRST, sw2=Curve.PRIME256)
        assert data.startswith(b"\x30")
