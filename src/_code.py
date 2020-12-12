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


def decode_be(b):
    x = 0
    for u in bytearray(b):
        x <<= 8
        x |= u
    return x


def encode_be(x):
    b = []
    while x >= 0x100:
        b.append(x & 0xff)
        x >>= 8
    b.append(x)                 # always one byte even if zero
    return bytes(bytearray(reversed(b)))
