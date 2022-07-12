#include <string.h>
#include <stdint.h>


#pragma once

typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

// field element
typedef i32 fe[10];

// Poly1305
typedef struct {
	uint32_t r[4];   // constant multiplier (from the secret key)
	uint32_t h[5];   // accumulated hash
	uint8_t  c[16];  // chunk of the message
	uint32_t pad[4]; // random number added at the end (from the secret key)
	size_t   c_idx;  // How many bytes are there in the chunk.
} crypto_poly1305_ctx;


static size_t align(size_t x, size_t pow_2);
static u32 load32_le(const u8 s[4]);
static void load32_le_buf(u32 *dst, const u8 *src, size_t size);
static void store32_le(u8 out[4], u32 in);
static void store32_le_buf(u8 *dst, const u32 *src, size_t size);
void crypto_wipe(void *secret, size_t size);
static u32 rotl32(u32 x, u32 n);
static void chacha20_rounds(u32 out[16], const u32 in[16]);
void crypto_hchacha20(u8 out[32], const u8 key[32], const u8 in[16]);

u64 crypto_chacha20_ctr(u8 *cipher_text, const u8 *plain_text,
	size_t text_size, const u8 key[32], const u8 nonce[8],
	u64 ctr);

u32 crypto_ietf_chacha20_ctr(u8 *cipher_text, const u8 *plain_text,
	size_t text_size,
	const u8 key[32], const u8 nonce[12], u32 ctr);

u64 crypto_xchacha20_ctr(u8 *cipher_text, const u8 *plain_text,
	size_t text_size,
	const u8 key[32], const u8 nonce[24], u64 ctr);


void crypto_chacha20(u8 *cipher_text, const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[8]);

void crypto_ietf_chacha20(u8 *cipher_text, const u8 *plain_text,
	size_t text_size,
	const u8 key[32], const u8 nonce[12]);


void crypto_xchacha20(u8 *cipher_text, const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[24]);




static void poly_block(crypto_poly1305_ctx *ctx, const u8 in[16], unsigned end);


void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32]);

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
	const u8 *message, size_t message_size);


void crypto_poly1305_final(crypto_poly1305_ctx *ctx, u8 mac[16]);


void crypto_poly1305(u8     mac[16], const u8 *message,
	size_t message_size, const u8  key[32]);


static void lock_auth(u8 mac[16], const u8  auth_key[32],
	const u8 *ad, size_t ad_size,
	const u8 *cipher_text, size_t text_size);

void crypto_lock_aead(u8 mac[16], u8 *cipher_text,
	const u8  key[32], const u8  nonce[24],
	const u8 *ad, size_t ad_size,
	const u8 *plain_text, size_t text_size);

void crypto_lock(u8 mac[16], u8 *cipher_text,
	const u8 key[32], const u8 nonce[24],
	const u8 *plain_text, size_t text_size);

int crypto_unlock(u8 *plain_text,
	const u8 key[32], const u8 nonce[24], const u8 mac[16],
	const u8 *cipher_text, size_t text_size);

int crypto_unlock_aead(u8 *plain_text, const u8 key[32], const u8 nonce[24],
	const u8  mac[16],
	const u8 *ad, size_t ad_size,
	const u8 *cipher_text, size_t text_size);

int crypto_verify16(const u8 a[16], const u8 b[16]);

static int neq0(u64 diff);

static u64 x16(const u8 a[16], const u8 b[16]);

static u64 load64_le(const u8 s[8]);


void crypto_x25519(u8       raw_shared_secret[32],
	const u8 your_secret_key[32],
	const u8 their_public_key[32]);

static void fe_mul(fe h, const fe f, const fe g);