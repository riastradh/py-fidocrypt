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
from cryptography.hazmat.primitives.constant_time import bytes_eq
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap2 import AttestedCredentialData
from fido2.server import Fido2Server

from ._curve import NISTP256
from ._recover import ecdsa_recover_pubkey


class Fido2KDFServer(Fido2Server):
    def __init__(self, *args, **kwargs):
        super(Fido2KDFServer, self).__init__(*args, **kwargs)
        self.allowed_algorithms = [
            alg for alg in self.allowed_algorithms
            if alg.alg == ES256.ALGORITHM
        ]
        assert self.allowed_algorithms, 'Missing ECDSA support'

    def register_complete_kdf(self, state, client_data, attestation_object):
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
        pkconf = sha256(b'FIDOKDF1' + pkcbor).digest()
        key = sha256(b'FIDOKDF2' + pkcbor).digest()

        return {credential_id: pkconf}, key

    def authenticate_complete_kdf(
            self, state, pkconfs, credential_id, client_data, auth_data,
            signature
    ):
        if credential_id not in pkconfs:
            raise Exception('Unrecognized credential id')
        pkconf = pkconfs[credential_id]
        message = auth_data + client_data.hash

        pycapos, pycaneg = ecdsa_recover_pubkey(
            signature, message, NISTP256, hashes.SHA256()
        )
        pkpos = ES256.from_cryptography_key(pycapos)
        pkneg = ES256.from_cryptography_key(pycaneg)

        def confirm(pkcbor):
            return bytes_eq(pkconf, sha256(b'FIDOKDF1' + pkcbor).digest())

        def complete(public_key, pkcbor):
            credentials = [AttestedCredentialData.create(
                b'\0' * 16, credential_id, public_key
            )]
            self.authenticate_complete(
                state, credentials, credential_id, client_data, auth_data,
                signature
            )
            return sha256(b'FIDOKDF2' + pkcbor).digest()

        pkposcbor = cbor.encode(pkpos)
        if confirm(pkposcbor):
            return complete(pkpos, pkposcbor)

        pknegcbor = cbor.encode(pkneg)
        if confirm(pknegcbor):
            return complete(pkneg, pknegcbor)

        raise Exception('Key mismatch')
