# -*- coding: utf-8 -*-

#  Copyright 2020 Taylor R Campbell
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Deterministic authenticated encryption with HMAC-SHA256 and ChaCha20
# in SIV -- won't break any speed records but it'll serve for this
# low-performance application, and everyone and their dog has the parts
# lying around handy.
#
#       Given key, header, and payload, the 32-byte tag is
#
#               HMAC-SHA256(key, header || payload ||
#                       le64(nbytes(header)) || le64(nbytes(payload)) || 0),
#
#       the derived 32-byte subkey is
#
#               HMAC-SHA256(key, tag || 1),
#
#       and the (unauthenticated) ciphertext is
#
#               payload ^ ChaCha20_subkey(0);
#
#       finally, the authenticated ciphertext is the concatenation
#
#               tag || (payload ^ ChaCha20_subkey(0)).
#
#       Decryption and verification are defined the obvious way.  The
#       tag (or, indeed, any substring of the ciphertext) is a
#       commitment to the key and the payload as long as HMAC-SHA256 is
#       collision-resistant.
#

import hmac
import struct

from hashlib import sha256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms


def encrypt(key, header, payload):
    assert isinstance(key, bytes), type(key)
    assert len(key) == 32
    assert isinstance(header, bytes), type(header)
    assert isinstance(payload, bytes), type(payload)
    tag = _auth(key, header, payload)
    return tag + _stream_xor(key, tag, payload)


def decrypt(key, header, ciphertext):
    assert isinstance(key, bytes)
    assert len(key) == 32
    assert isinstance(header, bytes)
    assert isinstance(ciphertext, bytes)
    if len(ciphertext) < 32:
        raise Exception
    tag = ciphertext[:32]
    payload = _stream_xor(key, tag, ciphertext[32:])
    if not bytes_eq(tag, _auth(key, header, payload)):
        raise Exception
    return payload


def _auth(key, header, payload):
    # HMAC-SHA256(key, header || payload ||
    #   le64(nbytes(header)) || le64(nbytes(payload)) || 0)
    assert isinstance(key, bytes)
    assert len(key) == 32
    assert isinstance(header, bytes)
    assert isinstance(payload, bytes)
    h = hmac.new(key, digestmod=sha256)
    h.update(header)
    h.update(payload)
    h.update(struct.pack('<Q', len(header)))
    h.update(struct.pack('<Q', len(payload)))
    h.update(b'\x00')           # domain separation
    return h.digest()


def _kdf(key, tag):
    # HMAC-SHA256(key, tag || 1)
    assert isinstance(key, bytes)
    assert len(key) == 32
    assert isinstance(tag, bytes)
    assert len(tag) == 32
    h = hmac.new(key, digestmod=sha256)
    h.update(tag)
    h.update(b'\x01')           # domain separation
    return h.digest()


def _stream_xor(key, tag, payload):
    # subkey := HMAC-SHA256(key, tag || 1)
    # payload ^ ChaCha20_subkey(0)
    assert isinstance(key, bytes)
    assert len(key) == 32
    assert isinstance(tag, bytes)
    assert len(tag) == 32
    subkey = _kdf(key, tag)
    nonce = bytearray(16)
    alg = algorithms.ChaCha20(subkey, nonce)
    cipher = Cipher(alg, mode=None, backend=default_backend())
    return cipher.encryptor().update(payload)
