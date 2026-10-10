/*
 * kat.c - known-answer test of the AWS-LC code, on whatever path the CPU (or
 * OPENSSL_ia32cap / OPENSSL_armcap) selects
 *
 *   kat <AWS-LC's crypto/cipher_extra/test directory>
 *
 * Runs the test vectors for the sizes shadowsocks uses (vectors with other
 * nonce or tag sizes must be rejected, never answered wrongly), then hashes
 * the output of every AEAD over lengths 0 to 69000, opening each result again
 * and checking that a tampered one fails, and of ChaCha20 across the 2^32
 * block counter wrap. The hash must be the same on every code path; any
 * change in output shows up there. SHA-1 is checked the same way, against
 * a value from another implementation. Exits non-zero on any failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/chacha.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "aws-lc-ss.h"

#define EXPECTED_DIGEST 0xe40ca485u
/* SHA-1 of lengths 0 to 2100 in various update splits, and of 2 MB, as
 * Python's hashlib computes it */
#define EXPECTED_SHA1 0x6ff725dbu

static size_t
unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    if (s[0] == '"') {  /* a quoted literal string */
        for (s++; *s && *s != '"'; s++)
            out[n++] = (uint8_t)*s;
        return n;
    }
    while (s[0] && s[0] != '\n' && s[1]) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static uint32_t
fnv(const uint8_t *p, size_t n, uint32_t h)
{
    while (n--) {
        h ^= *p++;
        h *= 16777619u;
    }
    return h;
}

/* One vector: seal must give CT and TAG, open must give IN back, and open
 * must fail once the last byte is flipped. Returns 1 if it passed.
 */
static int
check_vector(const EVP_AEAD *a, const uint8_t *key, size_t kl,
             const uint8_t *nonce, size_t nl, const uint8_t *in, size_t il,
             const uint8_t *ad, size_t al, const uint8_t *ct, size_t cl,
             const uint8_t *tag, size_t tl, int *rejected)
{
    static uint8_t out[8192], back[8192];
    EVP_AEAD_CTX c;
    size_t ol, bl;
    int ok = 1;

    *rejected = 0;
    if (!EVP_AEAD_CTX_init(&c, a, key, kl, tl, NULL)) {
        *rejected = 1;
        return 0;
    }
    if (!EVP_AEAD_CTX_seal(&c, out, &ol, sizeof(out), nonce, nl, in, il, ad,
                           al)) {
        *rejected = 1;
        ok = 0;
    } else if (ol != cl + tl || memcmp(out, ct, cl) ||
               memcmp(out + cl, tag, tl)) {
        ok = 0;
    } else {
        if (!EVP_AEAD_CTX_open(&c, back, &bl, sizeof(back), nonce, nl, out,
                               ol, ad, al) || bl != il || memcmp(back, in, il))
            ok = 0;
        out[ol - 1] ^= 1;
        if (EVP_AEAD_CTX_open(&c, back, &bl, sizeof(back), nonce, nl, out, ol,
                              ad, al))
            ok = 0;
    }
    EVP_AEAD_CTX_cleanup(&c);
    return ok;
}

/* Runs the vectors of one file; returns the number that failed */
static int
run_file(const char *path, const EVP_AEAD *a, size_t want_nl, int *cases,
         int *rejected)
{
    static uint8_t key[64], nonce[64], in[4096], ad[4096], ct[4096], tag[64];
    static char line[16384];
    size_t kl = 0, nl = 0, il = 0, al = 0, cl = 0, tl = 0;
    int have = 0, fails = 0;
    FILE *f = fopen(path, "r");

    if (f == NULL) {
        printf("cannot open %s\n", path);
        return 1;
    }
    for (;;) {
        char *r = fgets(line, sizeof(line), f);
        if (r == NULL || line[0] == '\n') {
            if (have) {
                int rej, ok = check_vector(a, key, kl, nonce, nl, in, il, ad,
                                           al, ct, cl, tag, tl, &rej);
                if (nl != want_nl || tl != 16) {
                    /* a size shadowsocks does not use */
                    if (rej)
                        (*rejected)++;
                    else
                        fails += !ok;
                } else {
                    (*cases)++;
                    fails += !ok;
                }
                have = 0;
            }
            if (r == NULL)
                break;
            continue;
        }
        char *v = strchr(line, ':');
        if (v == NULL || line[0] == '#')
            continue;
        for (v++; *v == ' '; v++)
            ;
        if (!strncmp(line, "KEY:", 4)) {
            kl   = unhex(v, key);
            have = 1;
        } else if (!strncmp(line, "NONCE:", 6)) {
            nl = unhex(v, nonce);
        } else if (!strncmp(line, "IN:", 3)) {
            il = unhex(v, in);
        } else if (!strncmp(line, "AD:", 3)) {
            al = unhex(v, ad);
        } else if (!strncmp(line, "CT:", 3)) {
            cl = unhex(v, ct);
        } else if (!strncmp(line, "TAG:", 4)) {
            tl = unhex(v, tag);
        }
    }
    fclose(f);
    return fails;
}

int
main(int argc, char **argv)
{
    static const struct {
        const char *name;
        const EVP_AEAD *(*aead)(void);
        size_t key_len, nonce_len;
    } t[] = {
        { "aes_128_gcm",        EVP_aead_aes_128_gcm,        16, 12 },
        { "aes_192_gcm",        EVP_aead_aes_192_gcm,        24, 12 },
        { "aes_256_gcm",        EVP_aead_aes_256_gcm,        32, 12 },
        { "chacha20_poly1305",  EVP_aead_chacha20_poly1305,  32, 12 },
        { "xchacha20_poly1305", EVP_aead_xchacha20_poly1305, 32, 24 },
    };
    static uint8_t buf[1 << 21], out[70100], back[70100];
    int fails = 0, cases = 0, rejected = 0, rt = 0;
    uint32_t h = 2166136261u;
    char path[4096];

    if (argc != 2) {
        fprintf(stderr, "usage: %s <test vector dir>\n", argv[0]);
        return 2;
    }

    CRYPTO_library_init();
    printf("impl: %s\n", ss_crypto_impl());

    for (size_t i = 0; i < 5; i++) {
        snprintf(path, sizeof(path), "%s/%s_tests.txt", argv[1], t[i].name);
        fails += run_file(path, t[i].aead(), t[i].nonce_len, &cases,
                          &rejected);
    }
    printf("known answers: %d passed, %d failed, %d of other sizes rejected\n",
           cases - fails, fails, rejected);

    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (uint8_t)(i * 131 + 7);
    for (size_t i = 0; i < 5; i++) {
        for (size_t len = 0; len <= 69000;
             len += len < 300 ? 1 : len < 5000 ? 37 : 4999) {
            uint8_t key[32], n[24];
            size_t ol, bl;
            EVP_AEAD_CTX c;

            memset(key, (int)len, sizeof(key));
            memset(n, (int)(len >> 2), sizeof(n));
            EVP_AEAD_CTX_zero(&c);
            EVP_AEAD_CTX_init(&c, t[i].aead(), key, t[i].key_len, 16, NULL);
            EVP_AEAD_CTX_seal(&c, out, &ol, sizeof(out), n, t[i].nonce_len,
                              buf, len, buf + 1, len % 50);
            h = fnv(out, ol, h);
            if (!EVP_AEAD_CTX_open(&c, back, &bl, sizeof(back), n,
                                   t[i].nonce_len, out, ol, buf + 1, len % 50)
                || bl != len || memcmp(back, buf, len))
                rt++;
            out[len % ol] ^= 0x80;
            if (EVP_AEAD_CTX_open(&c, back, &bl, sizeof(back), n,
                                  t[i].nonce_len, out, ol, buf + 1, len % 50))
                rt++;
            EVP_AEAD_CTX_cleanup(&c);
        }
    }
    for (uint32_t ctr = 0xfffffff0u; ctr != 0x10u; ctr++) {
        uint8_t key[32] = { 9 }, n[12] = { 7 };
        CRYPTO_chacha_20(out, buf, 2048, key, n, ctr);
        h = fnv(out, 2048, h);
    }
    for (size_t len = 0; len < 600; len++) {
        uint8_t key[32] = { (uint8_t)len }, n[12] = { 3 };
        CRYPTO_chacha_20(out, buf, len, key, n, (uint32_t)len);
        h = fnv(out, len, h);
    }
    {
        uint8_t key[32] = { 5 }, n[12] = { 3 };
        CRYPTO_chacha_20(out, buf, 65536, key, n, 0);
        h = fnv(out, 65536, h);
    }
    printf("digest: %08x (expected %08x), round trip and tamper failures: %d\n",
           h, EXPECTED_DIGEST, rt);

    uint32_t hs = 2166136261u;
    for (size_t len = 0; len <= 2100; len++) {
        size_t step = len % 7 == 0 ? len + 1 : len % 97 + 1, off = 0;
        uint8_t d[SHA_DIGEST_LENGTH];
        SHA_CTX c;

        SHA1_Init(&c);
        while (off < len) {
            size_t n = len - off < step ? len - off : step;
            SHA1_Update(&c, buf + off, n);
            off += n;
        }
        SHA1_Final(d, &c);
        hs = fnv(d, sizeof(d), hs);
    }
    {
        uint8_t d[SHA_DIGEST_LENGTH];
        SHA_CTX c;

        SHA1_Init(&c);
        SHA1_Update(&c, buf, sizeof(buf));
        SHA1_Final(d, &c);
        hs = fnv(d, sizeof(d), hs);
    }
    printf("sha1: %08x (expected %08x)\n", hs, EXPECTED_SHA1);

    fails += rt + (h != EXPECTED_DIGEST) + (hs != EXPECTED_SHA1) + (cases == 0);
    printf("RESULT: %s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}
