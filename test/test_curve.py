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


import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from fidocrypt._curve import NISTP256


def point(x, y, curve):
    n = ec.EllipticCurvePublicNumbers(x, y, curve.pyca)
    return n.public_key(backend=default_backend())


X = 0x12345
Y = 0x79812e03e6f5fdafa26699e4076fa550d9059b64eae5a28fc862b29506a170d


def test_equation():
    assert NISTP256.equation(X, Y)
    assert Y == NISTP256.recover_y(X)
    assert not NISTP256.equation(X, Y + 1)
    assert not NISTP256.equation(X + 1, Y)
    with pytest.raises(Exception):
        NISTP256.recover_y(0x123456789)


def test_neg():
    P = point(X, Y, NISTP256)
    Pneg = point(X, (-Y) % NISTP256.p, NISTP256)
    assert Pneg.public_numbers() == NISTP256.neg(P).public_numbers()
    assert P.public_numbers() == NISTP256.neg(Pneg).public_numbers()


def test_add_sub():
    P = point(X, Y, NISTP256)
    P2 = NISTP256.add(P, P)
    P3 = NISTP256.add(P2, P)
    assert P2.public_numbers() == NISTP256.sub(P3, P).public_numbers()
    assert NISTP256.sub(P, P) is None
