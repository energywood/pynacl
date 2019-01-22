from __future__ import absolute_import, division, print_function

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure

crypto_vrf_PUBLICKEYBYTES=lib.crypto_vrf_publickeybytes()
crypto_vrf_SECRETKEYBYTES=lib.crypto_vrf_secretkeybytes()
crypto_vrf_SEEDBYTES=lib.crypto_vrf_seedbytes()
crypto_vrf_PROOFBYTES=lib.crypto_vrf_proofbytes()
crypto_vrf_OUTPUTBYTES=lib.crypto_vrf_outputbytes()


def crypto_vrf_keypair():
    """
    Returns a randomly generated public key and secret key.

    :rtype: (bytes(public_key), bytes(secret_key))
    """
    pk = ffi.new("unsigned char[]", crypto_vrf_PUBLICKEYBYTES)
    sk = ffi.new("unsigned char[]", crypto_vrf_SECRETKEYBYTES)

    rc = lib.crypto_vrf_keypair(pk, sk)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return (
        ffi.buffer(pk, crypto_vrf_PUBLICKEYBYTES)[:],
        ffi.buffer(sk, crypto_vrf_SECRETKEYBYTES)[:],
    )

def crypto_vrf_keypair_from_seed(seed):
    """
    Computes and returns the public key and secret key using the seed ``seed``.

    :param seed: bytes
    :rtype: (bytes(public_key), bytes(secret_key))
    """
    if len(seed) != crypto_vrf_SEEDBYTES:
        raise exc.ValueError("Invalid seed")

    pk = ffi.new("unsigned char[]", crypto_vrf_PUBLICKEYBYTES)
    sk = ffi.new("unsigned char[]", crypto_vrf_SECRETKEYBYTES)

    rc = lib.crypto_vrf_keypair_from_seed(pk, sk, seed)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return (
        ffi.buffer(pk, crypto_vrf_PUBLICKEYBYTES)[:],
        ffi.buffer(sk, crypto_vrf_SECRETKEYBYTES)[:],
    )

def crypto_vrf_is_valid_key(pk):
    rc = lib.crypto_vrf_is_valid_key(pk)
    return rc == 1

def crypto_vrf_prove(message, sk):

    proof = ffi.new("unsigned char[]", crypto_vrf_PROOFBYTES)

    rc = lib.crypto_vrf_prove(proof, sk, message, len(message))
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return ffi.buffer(proof, crypto_vrf_PROOFBYTES)[:]

def crypto_vrf_verify(message, pk, proof):

    output = ffi.new("unsigned char[]", crypto_vrf_OUTPUTBYTES)
    rc = lib.crypto_vrf_verify(output, pk, proof, message, len(message))
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return ffi.buffer(output, crypto_vrf_OUTPUTBYTES)[:]
