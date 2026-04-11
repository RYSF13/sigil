#include "certify.h"
#include "keyring.h"
#include "util.h"
#include <sodium.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* SigilCSG:
   magic(8) version(1) targetFP(32) signerFP(32) signature(64) timestamp(4)
*/
#define CSG_LEN (8 + 1 + 32 + 32 + 64 + 4)

static void certs_dir(char *out, size_t n)
{
    char base[256];
    sigil_dir(base, sizeof base);
    snprintf(out, n, "%s/certs", base);
}

int certify_key(const SigilPubKey *target, const SigilSecKey *my_sec)
{
    uint8_t sig[64];
    unsigned long long siglen = 0;
    crypto_sign_detached(sig, &siglen, target->fp, 32, my_sec->sig_sec);

    uint8_t pkg[CSG_LEN];
    uint8_t *p = pkg;

    memcpy(p, SIGIL_CSG_MAGIC, 8); p += 8;
    *p++ = SIGIL_VERSION;
    memcpy(p, target->fp, 32); p += 32;
    memcpy(p, my_sec->fp, 32); p += 32;
    memcpy(p, sig, 64);        p += 64;
    put_u32le(p, (uint32_t)time(NULL));

    char dir[256];
    certs_dir(dir, sizeof dir);
    ensure_dir(dir);

    char t[65], s[65];
    fp_to_hex(t, target->fp);
    fp_to_hex(s, my_sec->fp);

    char path[600];
    snprintf(path, sizeof path, "%s/%.16s_%.16s.csg", dir, t, s);

    if (write_file(path, pkg, sizeof pkg) != 0) return 1;

    printf("Certified: %.16s signed by %.16s\n", t, s);
    return 0;
}

int certify_check(const SigilPubKey *target)
{
    char dir[256];
    certs_dir(dir, sizeof dir);

    DIR *d = opendir(dir);
    if (!d) {
        printf("No certifications found.\n");
        return 0;
    }

    char target_hex[65];
    fp_to_hex(target_hex, target->fp);

    int found = 0;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strncasecmp(ent->d_name, target_hex, 16) != 0) continue;

        char path[600];
        snprintf(path, sizeof path, "%s/%s", dir, ent->d_name);

        uint8_t *data; size_t len;
        if (read_file(path, &data, &len) != 0) continue;
        if (len != CSG_LEN) { free(data); continue; }
        if (memcmp(data, SIGIL_CSG_MAGIC, 8) != 0) { free(data); continue; }
        if (data[8] != SIGIL_VERSION) { free(data); continue; }

        const uint8_t *target_fp = data + 9;
        const uint8_t *signer_fp = data + 9 + 32;
        const uint8_t *sig       = data + 9 + 32 + 32;

        if (sodium_memcmp(target_fp, target->fp, 32) != 0) { free(data); continue; }

        char signer_hex[65];
        fp_to_hex(signer_hex, signer_fp);

        SigilPubKey signer;
        if (keyring_find_pub(&signer, signer_hex) != 0) {
            printf("  [?] Unknown signer %.16s\n", signer_hex);
            free(data);
            found++;
            continue;
        }

        int ok = (crypto_sign_verify_detached(sig, target->fp, 32, signer.sig_pub) == 0);
        printf("  [%s] %s <%s>\n", ok ? "OK" : "BAD", signer.name, signer.mail);

        key_free_pub(&signer);
        free(data);
        found++;
    }

    closedir(d);

    if (!found) printf("No certifications found for this key.\n");
    return 0;
}