#include "keyring.h"
#include "util.h"
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void path_public_dir(char *out, size_t n)
{
    char base[256];
    sigil_dir(base, sizeof base);
    snprintf(out, n, "%s/public", base);
}

static void path_private_dir(char *out, size_t n)
{
    char base[256];
    sigil_dir(base, sizeof base);
    snprintf(out, n, "%s/private", base);
}

static void path_certs_dir(char *out, size_t n)
{
    char base[256];
    sigil_dir(base, sizeof base);
    snprintf(out, n, "%s/certs", base);
}

static void path_config(char *out, size_t n)
{
    char base[256];
    sigil_dir(base, sizeof base);
    snprintf(out, n, "%s/config", base);
}

int keyring_init(void)
{
    char base[256], pubd[256], secd[256], certd[256];
    sigil_dir(base, sizeof base);
    path_public_dir(pubd, sizeof pubd);
    path_private_dir(secd, sizeof secd);
    path_certs_dir(certd, sizeof certd);

    if (ensure_dir(base) != 0) return -1;
    if (ensure_dir(pubd) != 0) return -1;
    if (ensure_dir(secd) != 0) return -1;
    if (ensure_dir(certd) != 0) return -1;
    return 0;
}

static int write_keyfile(const char *dir, const char *fphex, const char *ext,
                         const uint8_t *data, size_t len)
{
    char path[600];
    snprintf(path, sizeof path, "%s/%s.%s", dir, fphex, ext);
    return write_file(path, data, len);
}

int keyring_store_pub(const SigilPubKey *pub)
{
    if (keyring_init() != 0) return -1;

    uint8_t *bin; size_t len;
    if (key_pub_serialize(pub, &bin, &len) != 0) return -1;

    char fphex[65]; fp_to_hex(fphex, pub->fp);
    char dir[256]; path_public_dir(dir, sizeof dir);

    int r = write_keyfile(dir, fphex, "pub", bin, len);
    free(bin);
    return r;
}

int keyring_store_sec(const SigilSecKey *sec)
{
    if (keyring_init() != 0) return -1;

    uint8_t *bin; size_t len;
    if (key_sec_serialize(sec, &bin, &len) != 0) return -1;

    char fphex[65]; fp_to_hex(fphex, sec->fp);
    char dir[256]; path_private_dir(dir, sizeof dir);

    int r = write_keyfile(dir, fphex, "sec", bin, len);
    free(bin);
    return r;
}

static int find_unique_by_prefix(const char *dir, const char *prefix, const char *ext,
                                 char *out_path, size_t outlen)
{
    if (!is_hex_prefix_ok(prefix)) return -1;

    DIR *d = opendir(dir);
    if (!d) return -1;

    size_t plen = strlen(prefix);
    int count = 0;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;


        const char *dot = strrchr(ent->d_name, '.');
        if (!dot) continue;
        if (strcmp(dot + 1, ext) != 0) continue;

        if (strncasecmp(ent->d_name, prefix, plen) == 0) {
            count++;
            snprintf(out_path, outlen, "%s/%s", dir, ent->d_name);
        }
    }
    closedir(d);

    if (count != 1) return -1; /* 0=not found, >1=ambiguous */
    return 0;
}

int keyring_find_pub(SigilPubKey *pub, const char *fp_prefix_hex)
{
    char dir[256]; path_public_dir(dir, sizeof dir);
    char path[600];
    if (find_unique_by_prefix(dir, fp_prefix_hex, "pub", path, sizeof path) != 0)
        return -1;

    uint8_t *data; size_t len;
    if (read_file(path, &data, &len) != 0) return -1;
    int r = key_pub_parse(pub, data, len);
    free(data);
    return r;
}

int keyring_find_sec(SigilSecKey *sec, const char *fp_prefix_hex)
{
    char dir[256]; path_private_dir(dir, sizeof dir);
    char path[600];
    if (find_unique_by_prefix(dir, fp_prefix_hex, "sec", path, sizeof path) != 0)
        return -1;

    uint8_t *data; size_t len;
    if (read_file(path, &data, &len) != 0) return -1;
    int r = key_sec_parse(sec, data, len);
    free(data);
    return r;
}

void keyring_list(int sec_only)
{
    char pdir[256], sdir[256];
    path_public_dir(pdir, sizeof pdir);
    path_private_dir(sdir, sizeof sdir);

    DIR *d = opendir(pdir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        const char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot + 1, "pub") != 0) continue;

        char path[600];
        snprintf(path, sizeof path, "%s/%s", pdir, ent->d_name);

        uint8_t *data; size_t len;
        if (read_file(path, &data, &len) != 0) continue;

        SigilPubKey pub;
        if (key_pub_parse(&pub, data, len) == 0) {
            char fphex[65]; fp_to_hex(fphex, pub.fp);

            char secpath[600];
            snprintf(secpath, sizeof secpath, "%s/%s.sec", sdir, fphex);
            FILE *f = fopen(secpath, "rb");
            int has_sec = (f != NULL);
            if (f) fclose(f);

            if (!sec_only || has_sec) {
                printf("%-20s %-30s %.16s %s\n",
                       pub.name, pub.mail, fphex, has_sec ? "[sec]" : "");
            }
            key_free_pub(&pub);
        }
        free(data);
    }
    closedir(d);
}

int keyring_delete(const char *fp_prefix_hex)
{
    SigilPubKey pub;
    if (keyring_find_pub(&pub, fp_prefix_hex) != 0) return -1;

    char fphex[65]; fp_to_hex(fphex, pub.fp);
    key_free_pub(&pub);

    char pdir[256], sdir[256];
    path_public_dir(pdir, sizeof pdir);
    path_private_dir(sdir, sizeof sdir);

    char p[600], s[600];
    snprintf(p, sizeof p, "%s/%s.pub", pdir, fphex);
    snprintf(s, sizeof s, "%s/%s.sec", sdir, fphex);

    remove(p);
    remove(s);
    return 0;
}

int keyring_get_default(char *out_prefix, size_t outlen)
{
    char cfg[256];
    path_config(cfg, sizeof cfg);

    FILE *f = fopen(cfg, "r");
    if (!f) return -1;

    char line[256];
    int in_default = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strcmp(line, "[default]") == 0) { in_default = 1; continue; }
        if (!in_default) continue;

        const char *k = "fingerprint = ";
        if (strncmp(line, k, strlen(k)) == 0) {
            strncpy(out_prefix, line + strlen(k), outlen - 1);
            out_prefix[outlen - 1] = 0;
            fclose(f);
            return is_hex_prefix_ok(out_prefix) ? 0 : -1;
        }
    }
    fclose(f);
    return -1;
}

int keyring_set_default(const char *prefix)
{
    if (!is_hex_prefix_ok(prefix)) return -1;
    if (keyring_init() != 0) return -1;

    char cfg[256];
    path_config(cfg, sizeof cfg);

    FILE *f = fopen(cfg, "w");
    if (!f) return -1;

    fprintf(f, "[default]\n");
    fprintf(f, "fingerprint = %s\n", prefix);
    fclose(f);
    return 0;
}

int keyring_pick_only_secret(char *out_prefix, size_t outlen)
{
    char sdir[256];
    path_private_dir(sdir, sizeof sdir);

    DIR *d = opendir(sdir);
    if (!d) return -1;

    int count = 0;
    char one[256] = {0};

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        const char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot + 1, "sec") != 0) continue;
        count++;
        strncpy(one, ent->d_name, sizeof one - 1);
    }
    closedir(d);

    if (count != 1) return -1;


    char *dot = strrchr(one, '.');
    if (!dot) return -1;
    *dot = 0;


    size_t n = strlen(one);
    if (n < 16) return -1;

    strncpy(out_prefix, one, outlen - 1);
    out_prefix[outlen - 1] = 0;
    return 0;
}