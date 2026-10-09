/*
 * hkdf.h - HKDF-SHA1, replacing the one built on mbedTLS
 *
 * The AEAD ciphers derive each session's subkey with HKDF-SHA1 (SIP007); it
 * runs once per salt, never on the data path.
 */

#ifndef _SS_HKDF_H
#define _SS_HKDF_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_LENGTH 20

/* RFC 5869 with SHA-1. Returns 0, or -1 if okm_len exceeds 255 * 20. */
int ss_hkdf_sha1(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

#endif
