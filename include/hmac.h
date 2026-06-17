#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

#define HMAC_SIZE 32
#define TIMESTAMP_SIZE 8
#define HEADER_SIZE (HMAC_SIZE + TIMESTAMP_SIZE)

// 数据包格式: [32字节HMAC] + [8字节时间戳] + [数据]

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out);

int hmac_verify(const uint8_t *a, const uint8_t *b);
int timestamp_verify(uint64_t packet_ts, uint64_t now);

#endif
