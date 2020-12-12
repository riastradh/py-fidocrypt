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


from fidocrypt._code import decode_be
from fidocrypt._code import encode_be


def test_decode_be():
    assert decode_be([1, 2, 3]) == 0x010203
    assert decode_be([1, 2, 3, 4, 5, 6]) == 0x010203040506
    assert decode_be([1, 2, 3, 4, 5, 6, 7, 8, 9]) == 0x010203040506070809


def test_encode_be():
    assert encode_be(0) == bytes([0])
    assert encode_be(0x010203) == bytes([1, 2, 3])
    assert encode_be(0x010203040506) == bytes([1, 2, 3, 4, 5, 6])
    assert encode_be(0x010203040506070809) == \
        bytes([1, 2, 3, 4, 5, 6, 7, 8, 9])
