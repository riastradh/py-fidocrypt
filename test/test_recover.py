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


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fidocrypt._curve import NISTP256
from fidocrypt._recover import ecdsa_recover_pubkey


def test_golden():
    pass                        # XXX


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
