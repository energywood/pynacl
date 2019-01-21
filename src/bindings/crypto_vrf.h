/*
 * THREAD SAFETY: crypto_vrf_keypair() is thread-safe provided that
 * sodium_init() was called before.
 *
 * Other functions, including crypto_vrf_keypair_from_seed(), are always
 * thread-safe.
 */




size_t crypto_vrf_publickeybytes(void);

size_t crypto_vrf_secretkeybytes(void);

size_t crypto_vrf_seedbytes(void);

size_t crypto_vrf_proofbytes(void);

size_t crypto_vrf_outputbytes(void);


const char *crypto_vrf_primitive(void);

int crypto_vrf_keypair(unsigned char *pk, unsigned char *sk);

int crypto_vrf_keypair_from_seed(unsigned char *pk, unsigned char *sk,
				 const unsigned char *seed);

int crypto_vrf_is_valid_key(const unsigned char *pk);

int crypto_vrf_prove(unsigned char *proof, const unsigned char *sk,
		     const unsigned char *m, unsigned long long mlen);

int crypto_vrf_verify(unsigned char *output,
		      const unsigned char *pk,
		      const unsigned char *proof,
		      const unsigned char *m, unsigned long long mlen);

int crypto_vrf_proof_to_hash(unsigned char *hash, const unsigned char *proof);

void crypto_vrf_sk_to_pk(unsigned char *pk, const unsigned char *skpk);

void crypto_vrf_sk_to_seed(unsigned char *seed, const unsigned char *skpk);