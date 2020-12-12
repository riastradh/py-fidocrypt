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


from base64 import b64decode

from fidocrypt._dae import decrypt
from fidocrypt._dae import encrypt


KEY = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
])

HEADER = b'The Raven'

PAYLOAD = \
    b'Once upon a midnight dreary,\n' \
    b'  while I pondered, weak and weary,\n' \
    b'Over many a quaint and curious\n' \
    b'  volume of forgotten lore...\n'

CIPHERTEXT = b64decode('''
VciluRJIYbH3hJ1gyAz0nK+2N0wRZWgtLQv9v60doqW6TJYbBfMkeLeg7gqfaddFhu/iTXPiDjlz
YV4DSFpMxm9axdDTpwwJvadtp51nLwKJd9yVWRdMkJYOMaoTtB7qtv2nKQRc/X9msqon4nweSq2R
LUMfRrBpnJ9+KyFsYQoHawbOp9N+vPs6yJfWUu/Tt81J8IG6lx/G87DyMuo=
''')


def test_encrypt():
    assert encrypt(KEY, HEADER, PAYLOAD) == CIPHERTEXT


def test_decrypt():
    assert decrypt(KEY, HEADER, CIPHERTEXT) == PAYLOAD
