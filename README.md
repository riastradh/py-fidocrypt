Fidocrypt -- FIDO-based key derivation and encapsulation
========================================================

Taylor ‘Riastradh’ Campbell <campbell+fidocrypt@mumble.net>

**Fidocrypt** is a technique by which a server can store a secret in
the credential during U2F/FIDO/webauthn registration, and retrieve it
again during signin.  As long as the server erases its copy of the
secret, it cannot be retrieved again except by U2F/FIDO/webauthn
signin with the device.

The server-side credential storage of fidocrypt is necessarily slightly
different from standard webauthn credential storage.  Signin with
fidocrypt provides the same authentication guarantee as standard
webauthn -- it just also lets you retrieve a secret at the same time.

Fidocrypt works only with ECDSA over NIST P-256 (i.e., `ES256`/`P-256`,
in terms of [RFC 8152](https://tools.ietf.org/html/rfc8152)) -- it
could easily be extended to ECDSA over NIST P-384 or NIST P-521, but it
cannot be made to work with EdDSA (Ed25519 or Ed448) or RSASSA-PSS.

This Python implementation of fidocrypt is based on Yubico's
[python-fido2](https://github.com/Yubico/python-fido2) library.

#### [Protocol description](PROTOCOL.md)

Usage example
-------------

Replace `fido2.server.Fido2Server` by
`fidocrypt.cryptserver.Fido2CryptServer`:

```
from fidocrypt.cryptserver import Fido2CryptServer
```

Use it just like you would use `Fido2Server`, but instead of
`.register_complete` and `.authenticate_complete`, use
`.register_complete_encrypt` and `.authenticate_complete_decrypt`:

### Registration

```python
from fidocrypt.server import Fido2CryptServer
from fido2.webauthn import AttestationConveyancePreference
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType


RP = {'id': 'example.com', 'name': 'Example LLC'}

server = Fido2CryptServer(
    RP,
    attestation=AttestationConveyancePreference.DIRECT,
)

# Get the user id and the credentials that are already registered.
user = {'id': b'falken', 'name': 'Falken', 'display_name': 'Professor Falken'}
registered_credentials = ...            # load from database or create

# List the credential ids that are already registered for this user.
excluded_credentials = [
    PublicKeyCredentialDescriptor(
        type=PublicKeyCredentialType.PUBLIC_KEY,
        id=credential_id,
    )
    for credential_id in registered_credentials
]

# Get webauthn credential creation options.
create_options, state = server.register_begin(user, excluded_credentials)

# Send the create_options to the user through the web page using
# webauthn navigator.create, and remember the state.  When you get a
# response back consisting of client_data and attestation_object:

payload = b"a secret to be stored with the user's credentials"

# server.register_complete_encrypt returns a dict mapping credential_id
# to ciphertext.
credentials = server.register_complete_encrypt(
    state, payload, client_data, attestation_object
)

registered_credentials.update(credentials)
```

### Signin

```python
from fidocrypt.server import Fido2CryptServer
from fido2.webauthn import AttestationConveyancePreference
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType
from fido2.webauthn import UserVerificationRequirement


RP = {'id': 'example.com', 'name': 'Example LLC'}

server = Fido2CryptServer(
    RP,
    attestation=AttestationConveyancePreference.DIRECT,
)

# Get the credentials registered for this user.
registered_credentials = ...            # load from database

# List the credential ids that are registered for this user.
allowed_credentials = [
    PublicKeyCredentialDescriptor(
        type=PublicKeyCredentialType.PUBLIC_KEY,
        id=credential_id,
    )
    for credential_id in registered_credentials
]

# Get webauthn credential request options.
request_options, state = server.authenticate_begin(
    allowed_credentials,
    user_verification=UserVerificationRequirement.DISCOURAGED,
)

# Send the request_options to the user through the web page using
# webauthn navigator.get, and remember the state.  When you get a
# response back consisting of an attestation and client_data:

payload = server.authenticate_complete_decrypt(
    state,
    registered_credentials,
    assertion.credential['id'],
    client_data,
    assertion.auth_data,
    assertion.signature,
)
```
