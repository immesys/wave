/*
	a custom hash must have a 512bit digest and implement:

	struct ed25519_hash_context;

	void ed25519_hash_init(ed25519_hash_context *ctx);
	void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen);
	void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash);
	void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
*/

typedef int32_t ed25519_hash_context;

extern void HashInit(ed25519_hash_context *ctx);
extern void HashUpdate(ed25519_hash_context *ctx, uint8_t *in, size_t inlen);
extern void HashFinal(ed25519_hash_context *ctx, uint8_t *hash);
extern void Hash(uint8_t *hash, uint8_t *in, size_t inlen);

void ed25519_hash_init(ed25519_hash_context *ctx)
{
  HashInit(ctx);
}
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen)
{
  HashUpdate(ctx, (uint8_t*)in, inlen);
}
void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash)
{
  HashFinal(ctx, hash);
}
void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen)
{
  Hash(hash, (uint8_t*)in, inlen);
}
