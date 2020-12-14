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
import six

from six.moves.urllib.parse import urlparse

from fidocrypt.kdfserver import Fido2KDFServer
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject
from fido2.ctap2 import AuthenticatorData
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType
from fido2.webauthn import UserVerificationRequirement


public_suffixes = set()


RP = {'id': 'example.com', 'name': 'Example LLC'}
USER = {
    'id': b'falken',
    'name': 'Falken',
    'display_name': 'Professor Falken',
}

CREDENTIAL_ID = base64.b64decode('''
v3RAzNzQOJgR+zPy3MkATha/o7tN2dmJIB/XoJvslR70PEbg07DJuOo2nRb24KWpAwlMniekZ4bd
rPVQ9Wx4qA==
''')

PKCONF = base64.b64decode('''
dM2yp8Rrlz1KQxRPXpF0uMu3Dp8wmqWFLup8X6ppjrM=
''')

KEY = base64.b64decode('''
9rYZnFz0f/y8V1TfzrxfnH2CyZFjpv1TZizoShbMSMI=
''')

REGISTRATION = {
    'challenge': base64.b64decode(
        'pjpe5SAd6k/0lisO9VIXYG87C5x0iqAn0MdY/ILcKMU=',
    ),
    'attestation_object': AttestationObject(base64.b64decode('''
owFkbm9uZQJYxKN5pvbur7mlXjeMEYA04nUeaC+rny0wqxPSElWGzhlHQQAAAAEAAAAAAAAAAAAA
AAAAAAAAAEC/dEDM3NA4mBH7M/LcyQBOFr+ju03Z2YkgH9egm+yVHvQ8RuDTsMm46jadFvbgpakD
CUyeJ6Rnht2s9VD1bHiopQECAyYgASFYIFaOo9wsNRIW91R3ors7VN2f+mGslfzeEkyMlAISnDN/
IlggRytcE0E6WyiRhyH80R48+x+3izNxfse9Klya0dYApTYDoA==
''')),
    'client_data': ClientData(base64.b64decode('''
eyJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsICJvcmlnaW4iOiAidGVzdC1maWRvY3J5cHQ6Ly9l
eGFtcGxlLmNvbSIsICJjaGFsbGVuZ2UiOiAicGpwZTVTQWQ2a18wbGlzTzlWSVhZRzg3QzV4MGlx
QW4wTWRZX0lMY0tNVSIsICJjbGllbnRFeHRlbnNpb25zIjoge319
''')),
}

AUTHENTICATION = {
    'challenge': base64.b64decode(
        'cO4SMakXlpX2FTE15FcFzfztc6lkKHcjxt/Mx1CiG2A=',
    ),
    'client_data': ClientData(base64.b64decode('''
eyJ0eXBlIjogIndlYmF1dGhuLmdldCIsICJvcmlnaW4iOiAidGVzdC1maWRvY3J5cHQ6Ly9leGFt
cGxlLmNvbSIsICJjaGFsbGVuZ2UiOiAiY080U01ha1hscFgyRlRFMTVGY0Z6Znp0YzZsa0tIY2p4
dF9NeDFDaUcyQSIsICJjbGllbnRFeHRlbnNpb25zIjoge319
''')),
    'auth_data': AuthenticatorData(base64.b64decode(
        'o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAAFA==',
    )),
    'signature': base64.b64decode('''
MEUCIEHnDtBXDaAASxnanoVznHWimFBZdIE/eoC7vZgsJurkAiEAlF/DxlUxf52R4yWCUbcN8OYB
y2WCXhVMSHGA3yor/Rg=
'''),
}


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


def test_kdfserver_register():
    server = Fido2KDFServer(
        RP,
        verify_origin=rp_origin_verifier(RP['id']),
    )
    create_options, state = server.register_begin(
        USER,
        credentials=[PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=CREDENTIAL_ID,
        )],
        challenge=REGISTRATION['challenge'],
    )

    registered_credentials, key = server.register_complete_kdf(
        state,
        REGISTRATION['client_data'],
        REGISTRATION['attestation_object'],
    )
    assert registered_credentials == {CREDENTIAL_ID: PKCONF}
    assert key == KEY


def test_kdfserver_authenticate():
    server = Fido2KDFServer(
        RP,
        verify_origin=rp_origin_verifier(RP['id']),
    )
    request_options, state = server.authenticate_begin(
        credentials=[PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=CREDENTIAL_ID,
        )],
        user_verification=UserVerificationRequirement.DISCOURAGED,
        challenge=AUTHENTICATION['challenge'],
    )
    key = server.authenticate_complete_kdf(
        state,
        {CREDENTIAL_ID: PKCONF},
        CREDENTIAL_ID,
        AUTHENTICATION['client_data'],
        AUTHENTICATION['auth_data'],
        AUTHENTICATION['signature'],
    )
    assert key == KEY
