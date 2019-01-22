from __future__ import absolute_import, division, print_function

import nacl.bindings
import secrets
from nacl import encoding
from nacl import exceptions as exc
from nacl.utils import StringFixer, random

class Vrf():

    @staticmethod
    def generate():
        seed_len = nacl.bindings.crypto_vrf_SEEDBYTES
        seed = secrets.token_bytes(seed_len)
        return nacl.bindings.crypto_vrf_keypair_from_seed(seed)

    @staticmethod
    def prove(message, sk):
        return nacl.bindings.crypto_vrf_prove(message, sk)

    @staticmethod
    def is_valid_key(pk):
        return nacl.bindings.crypto_vrf_is_valid_key(pk)

    @staticmethod
    def verify(message, pk, proof):
        return nacl.bindings.crypto_vrf_verify(message, pk, proof)
