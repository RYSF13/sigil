#include "sign.h"
#include "armor.h"
#include "util.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* SigilSIG:
   magic(8) version(1) signerFP(32) signature(64) dataLen(4) data(L)
*/

int sigil_sign(const SigilSecKey *sec)
{
    uint8_t *data; size_t dlen;
    if (read_all_stream(stdin, &data, &dlen) != 0) return 1;

    uint8_t sig[64];
    unsigned long long siglen = 0;
    crypto_sign_detached(sig, &siglen, data, (unsigned long long)dlen, sec->sig_sec);

    size_t pkglen = 8 + 1 + 32 + 64 + 4 + dlen;
    uint8_t *pkg = (uint8_t *)malloc(pkglen);
    if (!pkg) { free(data); return 1; }

    uint8_t *p = pkg;
    memcpy(p, SIGIL_SIG_MAGIC, 8); p += 8;
    *p++ = SIGIL_VERSION;

    memcpy(p, sec->fp, 32); p += 32;
    memcpy(p, sig, 64);     p += 64;
    put_u32le(p, (uint32_t)dlen); p += 4;
    if (dlen) memcpy(p, data, dlen);

    armor_wrap("SIGNATURE", pkg, pkglen);

    sodium_memzero(data, dlen);
    free(data);
    free(pkg);
    return 0;
}

int sigil_verify(const SigilPubKey *maybe_pub)
{
    char *text;
    if (read_all_text(stdin, &text, NULL) != 0) return 1;

    uint8_t *pkg; size_t pkglen;
    if (armor_unwrap("SIGNATURE", text, &pkg, &pkglen) != 0) {
        free(text);
        fprintf(stderr, "sigil: invalid signature armor\n");
        return 2;
    }
    free(text);

    if (pkglen < 8 + 1 + 32 + 64 + 4) { free(pkg); return 2; }
    const uint8_t *p = pkg;

    if (memcmp(p, SIGIL_SIG_MAGIC, 8) != 0) { free(pkg); return 2; }
    p += 8;
    if (*p++ != SIGIL_VERSION) { free(pkg); return 2; }

    const uint8_t *signer_fp = p; p += 32;
    const uint8_t *sig       = p; p += 64;

    uint32_t dlen = get_u32le(p); p += 4;
    if ((size_t)(p - pkg) + dlen != pkglen) { free(pkg); return 2; }

    const SigilPubKey *pub = maybe_pub;
    SigilPubKey tmp;

    if (!pub) {
        char fphex[65]; fp_to_hex(fphex, signer_fp);

        extern int keyring_find_pub(SigilPubKey *pub, const char *fp_prefix_hex);
        if (keyring_find_pub(&tmp, fphex) != 0) {
            free(pkg);
            fprintf(stderr, "sigil: signer public key not found in keyring\n");
            return 2;
        }
        pub = &tmp;
    }

    int ok = (crypto_sign_verify_detached(sig, p, dlen, pub->sig_pub) == 0);

    if (!maybe_pub) key_free_pub(&tmp);
    free(pkg);

    if (!ok) {
        fprintf(stderr, "sigil: INVALID signature\n");
        return 2;
    }
    fprintf(stderr, "sigil: VALID signature\n");
    return 0;
}