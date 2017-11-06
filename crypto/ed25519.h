#ifndef ED25519_H
#define ED25519_H

#include <stdlib.h>

#if defined(WINSUPPORT)
#define ED25519_CUSTOMHASH 1
#define ED25519_CUSTOMRANDOM 1
#endif

#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

typedef unsigned char curved25519_key[32];

void bw_generate_keypair(unsigned char *private, unsigned char *public);
void bw_extsk(unsigned char* extsk, unsigned char *secret);
void bw_ed2curvePK(unsigned char* cpub, unsigned char *edpub);
void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);
int ed25519_sign_open(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);
void ed25519_sign(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);
void ed25519_sign_vector (const unsigned char **ms, size_t *mlens, size_t vlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);
int ed25519_sign_open_batch(const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid);

void ed25519_randombytes_unsafe(void *out, size_t count);

void curved25519_scalarmult_basepoint(curved25519_key pk, const curved25519_key e);

#if defined(__cplusplus)
}
#endif

#endif // ED25519_H
