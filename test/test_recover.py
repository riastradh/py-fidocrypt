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

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fidocrypt._curve import NISTP256
from fidocrypt._recover import ecdsa_recover_pubkey


def test_golden():
    msg = b'hello world'
    sig = base64.b64decode('''
MEUCICDIiNtVPTEWzqpSWEdtVB3CFlicI1wJXM5VtShAtgj+AiEAyaHdpTMhW6RU6tV6/VWipPfP
SlXakOq4Y68S7u8J6cM=
''')
    pkpos, pkneg = ecdsa_recover_pubkey(sig, msg, NISTP256, hashes.SHA256())
    pkpos.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    pkneg.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    x = 0x23ebed13f555cb01c19e3bb1acd09e7d03f42bcd3c00b5240714bdcfc9a596d
    y = 0xa4f2d67cf2aa26b56303c843668420c7ff90097fbd4a73af44885e1b14ae5c93
    pkn = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    assert pkpos.public_numbers() == pkn or pkneg.public_numbers() == pkn


def test_random():
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend=backend)
    pk = sk.public_key()
    msg = b'hello world'
    sig = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
    pk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    pkpos, pkneg = ecdsa_recover_pubkey(sig, msg, NISTP256, hashes.SHA256())
    pkpos.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    pkneg.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    assert pkpos.public_numbers() == pk.public_numbers() or \
        pkneg.public_numbers() == pk.public_numbers()
