from __future__ import absolute_import, division, print_function

import binascii

import pytest

from utils import assert_equal, assert_not_equal, read_crypto_test_vectors

from nacl.vrf import Vrf
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
 

class TestVRFKey:
    def test_initialize_with_generate(self):
        pk, sk = Vrf.generate()
        assert Vrf.is_valid_key(pk)
        message = b"test message"
        proof = Vrf.prove(message, sk)
        hash = Vrf.verify(message, pk, proof)
        assert len(hash) == 64
    

