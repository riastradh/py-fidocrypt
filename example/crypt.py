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
import os
import six
import sys
import threading

from six.moves.urllib.parse import urlparse

from fidocrypt.cryptserver import Fido2CryptServer
from fido2.client import Fido2Client
from fido2.ctap2 import AttestationObject
from fido2.attestation import NoneAttestation
from fido2.hid import CtapHidDevice
from fido2.hid import STATUS
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType
from fido2.webauthn import UserVerificationRequirement


devs = list(CtapHidDevice.list_devices())


def iterdevs(per_device):
    for dev in devs:
        return per_device(dev)


public_suffixes = set()


SCHEME = 'test-fidocrypt'


def fidocrypt_origin(rp_id):
    return 'test-fidocrypt://' + rp_id


def verify_origin(rp_id, origin):
    # Derived from fido2.rpid.verify_rp_id.
    if isinstance(rp_id, six.binary_type):
        rp_id = rp_id.decode()
    if not rp_id:
        return False
    if isinstance(origin, six.binary_type):
        origin = origin.decode()

    url = urlparse(origin)
    if url.scheme != SCHEME:
        return False
    if url.hostname == rp_id:
        return True
    if url.hostname.endswith('.' + rp_id) and rp_id not in public_suffixes:
        return True
    return False


def rp_origin_verifier(rp_id):
    return lambda origin: verify_origin(rp_id, origin)


def _fidocrypt_server(rp):
    return Fido2CryptServer(
        rp,
        verify_origin=rp_origin_verifier(rp['id']),
    )


def encrypt(payload, rp, user, exclude_credential_ids=set(), prompt=None):
    server = _fidocrypt_server(rp)
    challenge = os.urandom(32)
    create_options, state = server.register_begin(
        user,
        credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=credential_id,
            )
            for credential_id in sorted(exclude_credential_ids)
        ],
        challenge=challenge,
    )

    lock = threading.Lock()
    prompted = [False]

    def on_keepalive(status):
        if status == STATUS.UPNEEDED:
            done = False
            with lock:
                done = prompted[0]
                prompted[0] = True
            if not done:
                prompt()

    def per_device(dev, cancel_ev=None):
        client = Fido2Client(dev, fidocrypt_origin(rp['id']), verify_origin)
        return client.make_credential(
            create_options['publicKey'],
            on_keepalive=on_keepalive if prompt is not None else None,
            **({} if cancel_ev is None else {'event': cancel_ev})
        )

    attestation_object, client_data = iterdevs(per_device)

    # Strip out the device attestation for privacy.
    attestation_object = AttestationObject.create(
        NoneAttestation.FORMAT,
        attestation_object.auth_data,
        {},
    )

    return server.register_complete_encrypt(
        state, payload, client_data, attestation_object
    )


def decrypt(ciphertexts, rp, user, prompt=None):
    server = _fidocrypt_server(rp)
    challenge = os.urandom(32)
    descriptors = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=credential_id,
        )
        for credential_id in sorted(ciphertexts.keys())
    ]

    request_options, state = server.authenticate_begin(
        credentials=descriptors,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        challenge=challenge,
    )

    lock = threading.Lock()
    prompted = [False]

    def on_keepalive(status):
        if status == STATUS.UPNEEDED:
            done = False
            with lock:
                done = prompted[0]
                prompted[0] = True
            if not done:
                prompt()

    def per_device(dev, cancel_ev=None):
        client = Fido2Client(dev, fidocrypt_origin(rp['id']), verify_origin)
        return client.get_assertion(
            request_options['publicKey'],
            on_keepalive=on_keepalive if prompt is not None else None,
            **({} if cancel_ev is None else {'event': cancel_ev})
        )

    assertions, client_data = iterdevs(per_device)

    for assertion in assertions:
        # XXX try multiple?
        return server.authenticate_complete_decrypt(
            state,
            ciphertexts,
            assertion.credential['id'],
            client_data,
            assertion.auth_data,
            assertion.signature,
        )
    raise Exception('Decryption failed')


RP = {'id': 'example.com', 'name': 'Example LLC'}
USER = {
    'id': b'falken',
    'name': 'Falken',
    'display_name': 'Professor Falken',
}

prompted = [None]


def prompt():
    sys.stderr.write('tap key; waiting...')
    sys.stderr.flush()
    prompted[0] = True


def vis(s):
    return base64.urlsafe_b64encode(s).decode('utf-8')


payload = os.urandom(32)
print('payload %s' % (vis(payload),))

prompted[0] = False
ciphertexts = encrypt(payload, RP, USER, prompt=prompt)
if prompted[0]:
    sys.stderr.write('\n')
    sys.stderr.flush()

for credential_id, ciphertext in ciphertexts.items():
    print('credential_id %s' % (vis(credential_id),))
    print('ciphertext %s' % (vis(ciphertext),))

prompted[0] = False
payload_ = decrypt(ciphertexts, RP, USER, prompt=prompt)
if prompted[0]:
    sys.stderr.write('\n')
    sys.stderr.flush()

print('payload_ %s' % (vis(payload_),))

assert payload_ == payload
