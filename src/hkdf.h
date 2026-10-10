/*
 * hkdf.h - HKDF-SHA1
 *
 * The AEAD ciphers derive a subkey with HKDF-SHA1 (SIP007) for every salt:
 * once per TCP connection and direction, and for every UDP packet.
 */

#ifndef _SS_HKDF_H
#define _SS_HKDF_H

#include <stddef.h>
#include <stdint.h>

/* RFC 5869 with SHA-1. Returns 0, or -1 if okm_len exceeds 255 * 20. */
int ss_hkdf_sha1(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

#endif
