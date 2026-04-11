#include "key.h"
#include "util.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char *dup_str(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s);
    char *d = (char *)malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n + 1);
    return d;
}

void key_free_pub(SigilPubKey *k)
{
    if (!k) return;
    free(k->name); k->name = NULL;
    free(k->mail); k->mail = NULL;
}

void key_free_sec(SigilSecKey *k)
{
    if (!k) return;
    free(k->name); k->name = NULL;
    free(k->mail); k->mail = NULL;
    sodium_memzero(k->enc_sec, sizeof k->enc_sec);
    sodium_memzero(k->sig_sec, sizeof k->sig_sec);
}

void key_fingerprint(uint8_t fp[32],
                     const uint8_t enc_pub[32],
                     const uint8_t sig_pub[32],
                     const char *name, const char *mail)
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, enc_pub, 32);
    crypto_generichash_update(&st, sig_pub, 32);
    crypto_generichash_update(&st, (const uint8_t *)name, strlen(name));
    crypto_generichash_update(&st, (const uint8_t *)mail, strlen(mail));
    crypto_generichash_final(&st, fp, 32);
}

void fp_to_hex(char out[65], const uint8_t fp[32])
{
    bin2hex(out, fp, 32);
}

int key_generate(SigilPubKey *pub, SigilSecKey *sec,
                 const char *name, const char *mail)
{
    memset(pub, 0, sizeof *pub);
    memset(sec, 0, sizeof *sec);

    uint8_t enc_pub[32], enc_sec[32];
    crypto_kx_keypair(enc_pub, enc_sec);

    uint8_t sig_pub[32], sig_sec[64];
    crypto_sign_keypair(sig_pub, sig_sec);

    pub->name = dup_str(name);
    pub->mail = dup_str(mail);
    if (!pub->name || !pub->mail) return -1;

    memcpy(pub->enc_pub, enc_pub, 32);
    memcpy(pub->sig_pub, sig_pub, 32);
    pub->created = (uint32_t)time(NULL);
    key_fingerprint(pub->fp, pub->enc_pub, pub->sig_pub, pub->name, pub->mail);

    sec->encrypted = 0;
    memcpy(sec->fp, pub->fp, 32);
    sec->name = dup_str(name);
    sec->mail = dup_str(mail);
    if (!sec->name || !sec->mail) return -1;
    sec->created = pub->created;

    memcpy(sec->enc_sec, enc_sec, 32);
    memcpy(sec->sig_sec, sig_sec, 64);

    /* EncSecKey=96: enc_sec(32)+sig_sec(64) */
    memcpy(sec->encseckey, sec->enc_sec, 32);
    memcpy(sec->encseckey + 32, sec->sig_sec, 64);

    memset(sec->salt, 0, 16);
    memset(sec->nonce, 0, 24);
    return 0;
}

int key_pub_serialize(const SigilPubKey *pub, uint8_t **out, size_t *len)
{
    uint8_t nlen = (uint8_t)strlen(pub->name);
    uint8_t mlen = (uint8_t)strlen(pub->mail);
    uint16_t extra_len = 0;

    *len = 8 + 1 + 1 + 32 + 32 + 32 + 1 + nlen + 1 + mlen + 4 + 2 + extra_len;
    uint8_t *buf = (uint8_t *)malloc(*len);
    if (!buf) return -1;

    uint8_t *p = buf;
    memcpy(p, SIGIL_PUB_MAGIC, 8); p += 8;
    *p++ = SIGIL_VERSION;
    *p++ = SIGIL_ALG_25519;

    memcpy(p, pub->enc_pub, 32); p += 32;
    memcpy(p, pub->sig_pub, 32); p += 32;
    memcpy(p, pub->fp, 32);      p += 32;

    *p++ = nlen;
    memcpy(p, pub->name, nlen); p += nlen;

    *p++ = mlen;
    memcpy(p, pub->mail, mlen); p += mlen;

    put_u32le(p, pub->created); p += 4;

    put_u16le(p, extra_len); p += 2;
    /* v1: no extra */

    *out = buf;
    return 0;
}

int key_pub_parse(SigilPubKey *pub, const uint8_t *data, size_t len)
{
    memset(pub, 0, sizeof *pub);

    if (len < 8 + 1 + 1 + 32 + 32 + 32 + 1 + 1 + 4 + 2) return -1;
    if (memcmp(data, SIGIL_PUB_MAGIC, 8) != 0) return -1;

    const uint8_t *p = data + 8;
    if (*p++ != SIGIL_VERSION) return -1;
    if (*p++ != SIGIL_ALG_25519) return -1;

    memcpy(pub->enc_pub, p, 32); p += 32;
    memcpy(pub->sig_pub, p, 32); p += 32;
    memcpy(pub->fp, p, 32);      p += 32;

    uint8_t nlen = *p++;
    if ((size_t)(p - data) + nlen + 1 > len) return -1;
    pub->name = (char *)malloc(nlen + 1);
    if (!pub->name) return -1;
    memcpy(pub->name, p, nlen); pub->name[nlen] = 0;
    p += nlen;

    uint8_t mlen = *p++;
    if ((size_t)(p - data) + mlen + 4 + 2 > len) { key_free_pub(pub); return -1; }
    pub->mail = (char *)malloc(mlen + 1);
    if (!pub->mail) { key_free_pub(pub); return -1; }
    memcpy(pub->mail, p, mlen); pub->mail[mlen] = 0;
    p += mlen;

    pub->created = get_u32le(p); p += 4;

    uint16_t extra_len = get_u16le(p); p += 2;
    if ((size_t)(p - data) + extra_len != len) { key_free_pub(pub); return -1; }

    /* fingerprint */
    uint8_t fp2[32];
    key_fingerprint(fp2, pub->enc_pub, pub->sig_pub, pub->name, pub->mail);
    if (sodium_memcmp(fp2, pub->fp, 32) != 0) { key_free_pub(pub); return -1; }

    return 0;
}


int key_sec_serialize(const SigilSecKey *sec, uint8_t **out, size_t *len)
{
    uint8_t nlen = (uint8_t)strlen(sec->name);
    uint8_t mlen = (uint8_t)strlen(sec->mail);
    uint16_t extra_len = 0;

    *len = 8 + 1 + 1 + 1 + 32
         + 1 + nlen
         + 1 + mlen
         + 4
         + 16 + 24 + 96
         + 2 + extra_len;

    uint8_t *buf = (uint8_t *)malloc(*len);
    if (!buf) return -1;

    uint8_t *p = buf;
    memcpy(p, SIGIL_PRI_MAGIC, 8); p += 8;
    *p++ = SIGIL_VERSION;
    *p++ = SIGIL_ALG_25519;
    *p++ = sec->encrypted;

    memcpy(p, sec->fp, 32); p += 32;

    *p++ = nlen;
    memcpy(p, sec->name, nlen); p += nlen;

    *p++ = mlen;
    memcpy(p, sec->mail, mlen); p += mlen;

    put_u32le(p, sec->created); p += 4;

    memcpy(p, sec->salt, 16);  p += 16;
    memcpy(p, sec->nonce, 24); p += 24;
    memcpy(p, sec->encseckey, 96); p += 96;

    put_u16le(p, extra_len); p += 2;
    /* v1: no extra */

    *out = buf;
    return 0;
}

int key_sec_parse(SigilSecKey *sec, const uint8_t *data, size_t len)
{
    memset(sec, 0, sizeof *sec);

    if (len < 8 + 1 + 1 + 1 + 32 + 1 + 1 + 4 + 16 + 24 + 96 + 2) return -1;
    if (memcmp(data, SIGIL_PRI_MAGIC, 8) != 0) return -1;

    const uint8_t *p = data + 8;
    if (*p++ != SIGIL_VERSION) return -1;
    if (*p++ != SIGIL_ALG_25519) return -1;

    sec->encrypted = *p++;
    memcpy(sec->fp, p, 32); p += 32;

    uint8_t nlen = *p++;
    if ((size_t)(p - data) + nlen + 1 > len) return -1;
    sec->name = (char *)malloc(nlen + 1);
    if (!sec->name) return -1;
    memcpy(sec->name, p, nlen); sec->name[nlen] = 0;
    p += nlen;

    uint8_t mlen = *p++;
    if ((size_t)(p - data) + mlen + 4 + 16 + 24 + 96 + 2 > len) { key_free_sec(sec); return -1; }
    sec->mail = (char *)malloc(mlen + 1);
    if (!sec->mail) { key_free_sec(sec); return -1; }
    memcpy(sec->mail, p, mlen); sec->mail[mlen] = 0;
    p += mlen;

    sec->created = get_u32le(p); p += 4;

    memcpy(sec->salt, p, 16); p += 16;
    memcpy(sec->nonce, p, 24); p += 24;
    memcpy(sec->encseckey, p, 96); p += 96;

    uint16_t extra_len = get_u16le(p); p += 2;
    if ((size_t)(p - data) + extra_len != len) { key_free_sec(sec); return -1; }


    if (sec->encrypted == 0) {
        memcpy(sec->enc_sec, sec->encseckey, 32);
        memcpy(sec->sig_sec, sec->encseckey + 32, 64);
        if (key_sec_selfcheck_plain(sec) != 0) { key_free_sec(sec); return -1; }
    }

    return 0;
}

int key_sec_selfcheck_plain(const SigilSecKey *sec)
{
    uint8_t enc_pub[32];
    crypto_scalarmult_curve25519_base(enc_pub, sec->enc_sec);

    uint8_t sig_pub[32];
    crypto_sign_ed25519_sk_to_pk(sig_pub, sec->sig_sec);

    uint8_t fp2[32];
    key_fingerprint(fp2, enc_pub, sig_pub, sec->name, sec->mail);
    if (sodium_memcmp(fp2, sec->fp, 32) != 0) return -1;
    return 0;
}

int key_sec_encrypt(SigilSecKey *sec, const char *pass)
{
    uint8_t key[32];
    randombytes_buf(sec->salt, sizeof sec->salt);

    if (crypto_pwhash(key, sizeof key,
                      pass, strlen(pass),
                      sec->salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return -1;
    }

    /* plaintext80 = enc_sec32 || ed_seed32 || pad16(0) */
    uint8_t seed[32];
    crypto_sign_ed25519_sk_to_seed(seed, sec->sig_sec);

    uint8_t plain[80];
    memcpy(plain, sec->enc_sec, 32);
    memcpy(plain + 32, seed, 32);
    memset(plain + 64, 0, 16);

    randombytes_buf(sec->nonce, sizeof sec->nonce);

    uint8_t c[80];
    uint8_t tag[16];
    unsigned long long clen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        c, tag, &clen,
        plain, sizeof plain,
        NULL, 0,              /* AD */
        NULL,
        sec->nonce,
        key
    );

    /* EncSecKey(96) = ciphertext80 || tag16 */
    memcpy(sec->encseckey, c, 80);
    memcpy(sec->encseckey + 80, tag, 16);

    sec->encrypted = 1;
    sodium_memzero(key, sizeof key);
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(plain, sizeof plain);
    return 0;
}

int key_sec_decrypt(SigilSecKey *sec, const char *pass)
{
    if (sec->encrypted == 0) return 0;

    uint8_t key[32];
    if (crypto_pwhash(key, sizeof key,
                      pass, strlen(pass),
                      sec->salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return -1;
    }

    uint8_t c[80];
    uint8_t tag[16];
    memcpy(c, sec->encseckey, 80);
    memcpy(tag, sec->encseckey + 80, 16);

    uint8_t plain[80];

    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            plain,
            NULL, /* nsec */
            c, (unsigned long long)sizeof c,
            tag,
            NULL, 0, /* ad */
            sec->nonce,
            key) != 0) {
        sodium_memzero(key, sizeof key);
        return -1;
    }

    memcpy(sec->enc_sec, plain, 32);

    uint8_t seed[32];
    memcpy(seed, plain + 32, 32);

    uint8_t sig_pub[32];
    crypto_sign_seed_keypair(sig_pub, sec->sig_sec, seed);

    sec->encrypted = 0;


    if (key_sec_selfcheck_plain(sec) != 0) {
        sodium_memzero(key, sizeof key);
        return -1;
    }

    sodium_memzero(key, sizeof key);
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(plain, sizeof plain);
    return 0;
}