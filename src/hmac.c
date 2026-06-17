#include "hmac.h"
#include "sha256.h"
#include <string.h>

#define HMAC_BLOCK_SIZE 64
#define REPLAY_WINDOW 300

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out) {
    SHA256_CTX ctx;
    uint8_t k_ipad[HMAC_BLOCK_SIZE];
    uint8_t k_opad[HMAC_BLOCK_SIZE];
    uint8_t key_hash[SHA256_BLOCK_SIZE];
    int i;

    if (key_len > HMAC_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_hash);
        key = key_hash;
        key_len = SHA256_BLOCK_SIZE;
    }

    __builtin_memset(k_ipad, 0x36, HMAC_BLOCK_SIZE);
    __builtin_memset(k_opad, 0x5c, HMAC_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, HMAC_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, out);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, HMAC_BLOCK_SIZE);
    sha256_update(&ctx, out, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, out);
}

int hmac_verify(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;
    int i;
    for (i = 0; i < HMAC_SIZE; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

int timestamp_verify(uint64_t packet_ts, uint64_t now) {
    if (packet_ts > now + 60) return 0;
    if (now - packet_ts > REPLAY_WINDOW) return 0;
    return 1;
}
