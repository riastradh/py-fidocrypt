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

# ## WARNING ###
#
# This code does not run in constant time -- it is riddled with timing
# side channels.  It is absolutely unfit for general-purpose use.
#
# ## WARNING ###


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from ._mod import inv
from ._mod import sqrt


class ShortWeierstrass(object):
    def __init__(self, p, n, a, b, pyca):
        self._p = p             # coordinate field modulus
        self._n = n             # scalar ring order
        self._a = a             # coefficient of x
        self._b = b             # constant term
        self._pyca = pyca       # pyca cryptography representation of curve

    @property
    def p(self):
        """Modulus of coordinate field."""
        return self._p

    @property
    def n(self):
        """Order of scalar ring."""
        return self._n

    @property
    def a(self):
        """Coefficient of x in short Weierstrass equation."""
        return self._a

    @property
    def b(self):
        """Constant term in short Weierstrass equation."""
        return self._b

    @property
    def pyca(self):
        """Pyca cryptography object representing the curve."""
        return self._pyca

    def equation(self, x, y):
        """Verify the curve equation for given x and y coordinates."""
        p, a, b = self.p, self.a, self.b
        return pow(y, 2, p) == (pow(x, 3, p) + a*x + b) % p

    def recover_y(self, x):
        """Return one of the two possible y coordinates for x."""
        p, a, b = self.p, self.a, self.b
        y = sqrt(pow(x, 3, p) + a*x + b, p)
        assert self.equation(x, y)
        return y

    def neg(self, P):
        """Return the negation of an EllipticCurvePublicKey, -P."""
        if P is None:
            return None
        p = self.p
        x = P.public_numbers().x
        y = P.public_numbers().y
        n = ec.EllipticCurvePublicNumbers(x, (-y) % p, self.pyca)
        return n.public_key(backend=default_backend())

    def sub(self, P1, P2):
        """Return the difference of EllipticCurvePublicKeys, P1 - P2."""
        return self.add(P1, self.neg(P2))

    def add(self, P1, P2):
        """Return the sum of EllipticCurvePublicKeys, P1 + P2."""
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        p, a = self.p, self.a
        x1 = P1.public_numbers().x
        y1 = P1.public_numbers().y
        x2 = P2.public_numbers().x
        y2 = P2.public_numbers().y
        assert self.equation(x1, y1)
        assert self.equation(x2, y2)
        # https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html
        if x1 != x2:
            # addition
            x3 = ((y2 - y1)**2 * inv((x2 - x1)**2, p) - x1 - x2) % p
            y3 = ((2 * x1 + x2) * (y2 - y1) * inv(x2 - x1, p)
                  - (y2 - y1)**3 * inv((x2 - x1)**3, p)
                  - y1) % p
        elif y1 != y2:
            # P1 = -P2, P1 + P2 = O
            assert y1 % p == (-y2) % p
            return None
        else:
            # doubling
            x3 = ((3 * x1**2 + -3)**2 * inv((2 * y1)**2, p) - 2 * x1) % p
            y3 = (3 * x1 * (3 * x1**2 + a) * inv(2 * y1, p) -
                  (3 * x1**2 + a)**3 * inv((2 * y1)**3, p)
                  - y1) % p
        assert self.equation(x3, y3)
        n = ec.EllipticCurvePublicNumbers(x3, y3, self.pyca)
        return n.public_key(backend=default_backend())


NISTP256 = ShortWeierstrass(
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    a=-3,
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    pyca=ec.SECP256R1(),
)
