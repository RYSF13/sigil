#include "crypto.h"
#include "armor.h"
#include "util.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* SigilMSG:
   magic(8) version(1) recipientFP(32) ephPub(32) nonce(24) clen(4) cipher(L)
*/

int crypto_encrypt_to(const SigilPubKey *recipient)
{
    uint8_t *plain; size_t plen;
    if (read_all_stream(stdin, &plain, &plen) != 0) return 1;

    uint8_t eph_pk[32], eph_sk[32];
    crypto_kx_keypair(eph_pk, eph_sk);

    uint8_t shared[32];
    if (crypto_scalarmult_curve25519(shared, eph_sk, recipient->enc_pub) != 0) {
        free(plain); return 1;
    }

    uint8_t session[32];
    crypto_generichash(session, sizeof session, shared, sizeof shared, NULL, 0);

    uint8_t nonce[24];
    randombytes_buf(nonce, sizeof nonce);

    size_t maxclen = plen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *cipher = (uint8_t *)malloc(maxclen);
    if (!cipher) { free(plain); return 1; }

    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher, &clen,
            plain, (unsigned long long)plen,
            NULL, 0,       /* AD */
            NULL,
            nonce,
            session) != 0) {
        free(cipher); free(plain); return 1;
    }

    size_t pkglen = 8 + 1 + 32 + 32 + 24 + 4 + (size_t)clen;
    uint8_t *pkg = (uint8_t *)malloc(pkglen);
    if (!pkg) { free(cipher); free(plain); return 1; }

    uint8_t *p = pkg;
    memcpy(p, SIGIL_MSG_MAGIC, 8); p += 8;
    *p++ = SIGIL_VERSION;

    memcpy(p, recipient->fp, 32); p += 32;
    memcpy(p, eph_pk, 32);        p += 32;
    memcpy(p, nonce, 24);         p += 24;

    put_u32le(p, (uint32_t)clen); p += 4;
    memcpy(p, cipher, (size_t)clen);

    armor_wrap("MESSAGE", pkg, pkglen);

    sodium_memzero(shared, sizeof shared);
    sodium_memzero(session, sizeof session);
    sodium_memzero(eph_sk, sizeof eph_sk);
    sodium_memzero(plain, plen);

    free(pkg);
    free(cipher);
    free(plain);
    return 0;
}

int crypto_decrypt_with(const SigilSecKey *sec)
{
    char *text;
    if (read_all_text(stdin, &text, NULL) != 0) return 1;

    uint8_t *pkg; size_t pkglen;
    if (armor_unwrap("MESSAGE", text, &pkg, &pkglen) != 0) {
        free(text);
        fprintf(stderr, "sigil: invalid message armor\n");
        return 2;
    }
    free(text);

    if (pkglen < 8 + 1 + 32 + 32 + 24 + 4) { free(pkg); return 2; }
    const uint8_t *p = pkg;

    if (memcmp(p, SIGIL_MSG_MAGIC, 8) != 0) { free(pkg); return 2; }
    p += 8;
    if (*p++ != SIGIL_VERSION) { free(pkg); return 2; }

    const uint8_t *recipient_fp = p; p += 32;
    const uint8_t *eph_pub      = p; p += 32;
    const uint8_t *nonce        = p; p += 24;

    uint32_t clen = get_u32le(p); p += 4;
    if ((size_t)(p - pkg) + clen != pkglen) { free(pkg); return 2; }

    if (sodium_memcmp(recipient_fp, sec->fp, 32) != 0) {
        free(pkg);
        fprintf(stderr, "sigil: message not for this private key\n");
        return 2;
    }

    uint8_t shared[32];
    if (crypto_scalarmult_curve25519(shared, sec->enc_sec, eph_pub) != 0) {
        free(pkg); return 1;
    }

    uint8_t session[32];
    crypto_generichash(session, sizeof session, shared, sizeof shared, NULL, 0);

    size_t plen = (size_t)clen;
    if (plen < crypto_aead_xchacha20poly1305_ietf_ABYTES) { free(pkg); return 2; }
    plen -= crypto_aead_xchacha20poly1305_ietf_ABYTES;

    uint8_t *plain = (uint8_t *)malloc(plen ? plen : 1);
    if (!plain) { free(pkg); return 1; }

    unsigned long long outlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain, &outlen,
            NULL,
            p, (unsigned long long)clen,
            NULL, 0,
            nonce,
            session) != 0) {
        free(plain); free(pkg);
        fprintf(stderr, "sigil: decryption failed\n");
        return 2;
    }

    fwrite(plain, 1, (size_t)outlen, stdout);

    sodium_memzero(shared, sizeof shared);
    sodium_memzero(session, sizeof session);
    sodium_memzero(plain, (size_t)outlen);
    free(plain);
    free(pkg);
    return 0;
}