Fidocrypt -- FIDO-based key derivation and encapsulation
========================================================

Taylor ‘Riastradh’ Campbell <campbell+fidocrypt@mumble.net>

**Fidocrypt** is a technique by which a server can store a secret in
the credential during U2F/FIDO/webauthn registration, and retrieve it
again during signin.  As long as the server erases its copy of the
secret, and as long as the U2F device isn't badly designed (see below
on security), the secret cannot be retrieved again except by
U2F/FIDO/webauthn signin with the device.

For example, if a server holds the share of a key to encrypt a user's
password vault, you might store this share as the fidocrypt secret --
and store the _same_ share with every credential registered by the
user, so any one of their U2F keys not only serves to sign in but also
serves to decrypt the share.

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

Credit: I first learned about this technique from Joseph Birr-Paxton's
blog post on [abusing U2F to ‘store’
keys](https://jbp.io/2015/11/23/abusing-u2f-to-store-keys.html).

I then:

- adapted it from U2F to webauthn;

- tweaked it to verify the signature too so you get the same
  authentication guarantees as standard webauthn (under standard
  assumptions about SHA-256); and

- tweaked it to store a secret with the credential that can be
  decrypted with a key derived from the device, rather than just
  exposing the key directly, so that you can store the _same_ secret
  encrypted differently with many U2F devices.

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

registered_credentials.update(credentials)      # update database
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
# an authenticator assertion response back:

payload = server.authenticate_complete_decrypt(
    state,
    registered_credentials,
    assertion.credential['id'],
    client_data,
    assertion.auth_data,
    assertion.signature,
)
```

Security
--------

On most U2F devices, the public key is effectively a pseudorandom
function (with nonuniform distribution) of the credential id.
Typically, the credential id (or key handle, in the older U2F
nomenclature) is either

1. an authenticated ciphertext containing a private key generated on
   the device, under a symmetric secret key stored on the device, as in
   [current Yubico models][yubico-keygen]; or

2. a random input to a PRF which is used to derive the private key from
   it, along with an authenticator on the random input under a
   symmetric key stored on the device, as in [past Yubico
   models][yubico-keygen-old], SoloKeys (key generation:
   [(1)][solokeys-keygen1], [(2)][solokeys-keygen2]; key loading:
   [(1)][solokeys-keyload1], [(2)][solokeys-keyload2]), and likely
   other devices too.

In principle, a badly designed U2F device could expose the public key
in the credential id.  I don't know of any that do this, and it would
be quite a waste of space since for a credential id since the
credential id already has to determine a ~256-bit private key and have
a ~128-bit authenticator on it, and a public key is usually at least 32
bytes long.

That said, like all U2F-based systems, you should use fidocrypt as one
factor in multi-factor authentication -- use it to encrypt a single
share of a key to decrypt a password vault or laptop disk, not the
whole key, and combine it with another key derived from a password or
software storage device or similar.


  [yubico-keygen]: https://developers.yubico.com/U2F/Protocol_details/Key_generation.html
  [yubico-keygen-old]: https://web.archive.org/web/20190712075231/https://developers.yubico.com/U2F/Protocol_details/Key_generation.html
  [solokeys-keygen1]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/u2f.c#L180-L187
  [solokeys-keygen2]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/crypto.c#L273-L284
  [solokeys-keyload1]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/u2f.c#L250-L252
  [solokeys-keyload2]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/u2f.c#L164-L168
  [solokeys-keyload3]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/crypto.c#L210-L216
