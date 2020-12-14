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


from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils \
    import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec

from ._code import decode_be
from ._mod import inv


def ecdsa_recover_pubkey(signature, message, curve, hashalg):
    backend = default_backend()
    # The signature satisfies
    #
    #   r = x(H(m) s^{-1} * B + r s^{-1} * A);
    #
    # our goal is to solve for A.  We know
    #
    #   R = H(m) s^{-1} * B + r s^{-1} * A,
    # so
    #   A = r^{-1} s * (R - H(m) s^{-1} * B),
    #
    # but the equation is invariant under sign change for R.  Further,
    # pyca doesn't provide a way to compute both coordinates of scalar
    # multiplication -- only the x coordinate.  So we verify the
    # signature to find the matching A for each of the two possible
    # values of R, and we arrange it this way, rather than the usual
    # r^{-1} (s * R - H(m) * B), in order to avoid having to compute
    # more than one variable-base scalar multiplication.
    #
    r, s = decode_dss_signature(signature)

    r_ = inv(r, curve.n)
    s_ = inv(s, curve.n)

    hasher = hashes.Hash(hashalg, backend=backend)
    hasher.update(message)
    h = decode_be(hasher.finalize())            # H(m) as integer
    hs_ = (h * s_) % curve.n                    # H(m) s^{-1} * B
    hs_B = ec.derive_private_key(hs_, curve.pyca, backend=backend).public_key()
    r_s = (r_ * s) % curve.n                    # r^{-1} s
    P = ec.derive_private_key(r_s, curve.pyca, backend=backend)

    def recover(Rx, Ry):
        assert curve.equation(Rx, Ry)
        Rn = ec.EllipticCurvePublicNumbers(Rx, Ry, curve.pyca)
        R = Rn.public_key(backend=backend)
        R_hs_B = curve.sub(R, hs_B)             # R - H(m) s^{-1} * B
        ss = P.exchange(ec.ECDH(), R_hs_B)      # x(r^{-1} s (R - ...))
        Ax = decode_be(ss)
        Ay = curve.recover_y(Ax)
        assert curve.equation(Ax, Ay)
        An = ec.EllipticCurvePublicNumbers(Ax, Ay, curve.pyca)
        A = An.public_key(backend=backend)
        try:
            A.verify(signature, message, ec.ECDSA(hashalg))
            return A
        except InvalidSignature:
            A = curve.neg(A)
            A.verify(signature, message, ec.ECDSA(hashalg))
            return A

    Rx = r % curve.p
    Rypos = curve.recover_y(Rx)
    Ryneg = (-Rypos) % curve.p

    Apos = recover(Rx, Rypos)
    Aneg = recover(Rx, Ryneg)

    # Sanity check!
    Apos.verify(signature, message, ec.ECDSA(hashalg))
    Aneg.verify(signature, message, ec.ECDSA(hashalg))

    return Apos, Aneg
