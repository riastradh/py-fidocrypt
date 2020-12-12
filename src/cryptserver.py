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


from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap2 import AttestedCredentialData
from fido2.server import Fido2Server

from . import _dae
from ._curve import NISTP256
from ._recover import ecdsa_recover_pubkey


class Fido2CryptServer(Fido2Server):
    def __init__(self, *args, **kwargs):
        super(Fido2CryptServer, self).__init__(*args, **kwargs)
        self.allowed_algorithms = [
            alg for alg in self.allowed_algorithms
            if alg.alg == ES256.ALGORITHM
        ]
        assert self.allowed_algorithms, 'Missing ECDSA support'

    def register_complete_encrypt(
            self, state, payload, client_data, attestation_object
    ):
        auth_data = self.register_complete(
            state, client_data, attestation_object
        )
        credential_id = auth_data.credential_data.credential_id
        public_key = auth_data.credential_data.public_key

        if not isinstance(public_key, dict):
            raise Exception('Invalid public key')
        if set(public_key.keys()) != {1, 3, -1, -2, -3}:
            raise Exception('Malformed public key')
        if public_key[1] != 2:      # kty = verify
            raise Exception('Inappropriate public key type')
        if public_key[3] != ES256.ALGORITHM:    # alg = ES256, ECDSA w/ SHA-256
            raise Exception('Unsupported signature algorithm')
        if public_key[-1] != 1:     # curve = NIST P-256
            raise Exception('Unsupported ECDSA curve')
        if not isinstance(public_key[-2], bytes):
            raise Exception('Invalid x coordinate')
        if not isinstance(public_key[-3], bytes):
            raise Exception('Invalid y coordinate')

        pkcbor = cbor.encode(public_key)
        key = sha256(b'FIDOKDF0' + pkcbor).digest()
        ciphertext = _dae.encrypt(key, pkcbor, payload)

        return {credential_id: ciphertext}

    def authenticate_complete_decrypt(
            self, state, ciphertexts, credential_id, client_data, auth_data,
            signature
    ):
        if credential_id not in ciphertexts:
            raise Exception('Unrecognized credential id')
        ciphertext = ciphertexts[credential_id]
        message = auth_data + client_data.hash

        pycapos, pycaneg = ecdsa_recover_pubkey(
            signature, message, NISTP256, hashes.SHA256()
        )
        pkpos = ES256.from_cryptography_key(pycapos)
        pkneg = ES256.from_cryptography_key(pycaneg)

        def decrypt(pkcbor):
            key = sha256(b'FIDOKDF0' + pkcbor).digest()
            return _dae.decrypt(key, pkcbor, ciphertext)

        def complete(public_key, pkcbor):
            credentials = [AttestedCredentialData.create(
                b'\0' * 16, credential_id, public_key
            )]
            self.authenticate_complete(
                state, credentials, credential_id, client_data, auth_data,
                signature
            )

        pkposcbor = cbor.encode(pkpos)
        try:
            payload = decrypt(pkposcbor)
        except Exception:
            pass
        else:
            complete(pkpos, pkposcbor)
            return payload

        pknegcbor = cbor.encode(pkneg)
        try:
            payload = decrypt(pknegcbor)
        except Exception:
            pass
        else:
            complete(pkneg, pknegcbor)
            return payload

        raise Exception('Key mismatch')
