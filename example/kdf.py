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

from fidocrypt.kdfserver import Fido2KDFServer
from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.hid import STATUS
from fido2.webauthn import AttestationConveyancePreference
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType
from fido2.webauthn import UserVerificationRequirement


devs = list(CtapHidDevice.list_devices())


def iterdevs(per_device):
    for dev in devs:
        return per_device(dev)


public_suffixes = set()


SCHEME = 'fidokdf'


def fidokdf_origin(rp_id):
    return 'fidokdf://' + rp_id


def verify_origin(rp_id, origin):
    # Derived from fido2.rpid.verify_rp_id.
    if isinstance(rp_id, six.binary_type):
        rp_id = rp_id.decode()
    if not rp_id:
        sys.stderr.write('no rp_id %r\n' % (rp_id,))
        return False
    if isinstance(origin, six.binary_type):
        origin = origin.decode()

    url = urlparse(origin)
    if url.scheme != SCHEME:
        sys.stderr.write('bad scheme %r\n' % (url.scheme,))
        return False
    if url.hostname == rp_id:
        return True
    if url.hostname.endswith('.' + rp_id) and rp_id not in public_suffixes:
        return True
    return False


def rp_origin_verifier(rp_id):
    return lambda origin: verify_origin(rp_id, origin)


def _fidokdf_server(rp):
    return Fido2KDFServer(
        rp,
        attestation=AttestationConveyancePreference.DIRECT,
        verify_origin=rp_origin_verifier(rp['id']),
    )


def keygen(rp, user, exclude_credential_ids=set(), prompt=None):
    server = _fidokdf_server(rp)
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
        client = Fido2Client(dev, fidokdf_origin(rp['id']), verify_origin)
        return client.make_credential(
            create_options['publicKey'],
            on_keepalive=on_keepalive if prompt is not None else None,
            **({} if cancel_ev is None else {'event': cancel_ev})
        )

    attestation_object, client_data = iterdevs(per_device)

    return server.register_complete_kdf(
        state, client_data, attestation_object
    )


def derivekey(pkconfs, rp, user, prompt=None):
    server = _fidokdf_server(rp)
    challenge = os.urandom(32)
    descriptors = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=credential_id,
        )
        for credential_id in sorted(pkconfs.keys())
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
        client = Fido2Client(dev, fidokdf_origin(rp['id']), verify_origin)
        return client.get_assertion(
            request_options['publicKey'],
            on_keepalive=on_keepalive if prompt is not None else None,
            **({} if cancel_ev is None else {'event': cancel_ev})
        )

    assertions, client_data = iterdevs(per_device)

    return {
        assertion.credential['id']: server.authenticate_complete_kdf(
            state,
            pkconfs,
            assertion.credential['id'],
            client_data,
            assertion.auth_data,
            assertion.signature,
        )
        for assertion in assertions
    }


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


prompted[0] = False
pkconfs, key = keygen(RP, USER, prompt=prompt)
if prompted[0]:
    sys.stderr.write('\n')
    sys.stderr.flush()

credential_id = next(cid for cid in pkconfs.keys())
print('key %s' % (base64.urlsafe_b64encode(key).decode('utf8'),))

prompted[0] = False
key_ = derivekey(pkconfs, RP, USER, prompt=prompt)[credential_id]
if prompted[0]:
    sys.stderr.write('\n')
    sys.stderr.flush()
print('key_ %s' % (base64.urlsafe_b64encode(key_).decode('utf'),))

assert key_ == key
