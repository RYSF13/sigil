#include "util.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

void bin2hex(char *out, const uint8_t *in, size_t len)
{
    sodium_bin2hex(out, len * 2 + 1, in, len);
}

int hex2bin(uint8_t *out, size_t outlen, const char *hex)
{
    return sodium_hex2bin(out, outlen, hex, strlen(hex), NULL, NULL, NULL);
}

char *b64_encode(const uint8_t *in, size_t len)
{
    size_t b64len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    char *out = (char *)malloc(b64len);
    if (!out) return NULL;
    sodium_bin2base64(out, b64len, in, len, sodium_base64_VARIANT_ORIGINAL);
    return out;
}

int b64_decode(uint8_t **out, size_t *outlen, const char *in)
{
    size_t inlen = strlen(in);
    *out = (uint8_t *)malloc(inlen + 1);
    if (!*out) return -1;

    if (sodium_base642bin(*out, inlen + 1, in, inlen,
                          NULL, outlen, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        free(*out);
        *out = NULL;
        return -1;
    }
    return 0;
}

int read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    *len = (size_t)n;
    *out = (uint8_t *)malloc(*len ? *len : 1);
    if (!*out) { fclose(f); return -1; }

    if (*len && fread(*out, 1, *len, f) != *len) {
        free(*out); fclose(f); return -1;
    }
    fclose(f);
    return 0;
}

int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int read_all_stream(FILE *fp, uint8_t **out, size_t *len)
{
    size_t cap = 4096;
    size_t n = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return -1;

    for (;;) {
        size_t want = cap - n;
        size_t got = fread(buf + n, 1, want, fp);
        n += got;
        if (got == 0) break;
        if (n == cap) {
            cap *= 2;
            uint8_t *nb = (uint8_t *)realloc(buf, cap);
            if (!nb) { free(buf); return -1; }
            buf = nb;
        }
    }

    *out = buf;
    *len = n;
    return 0;
}

int read_all_text(FILE *fp, char **out, size_t *len)
{
    uint8_t *bin;
    size_t n;
    if (read_all_stream(fp, &bin, &n) != 0) return -1;
    char *s = (char *)realloc(bin, n + 1);
    if (!s) { free(bin); return -1; }
    s[n] = 0;
    *out = s;
    if (len) *len = n;
    return 0;
}

int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    if (mkdir(path, 0700) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
}

void sigil_dir(char *out, size_t len)
{
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(out, len, "%s/.sigil", home);
}

void put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}

uint16_t get_u16le(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

int is_hex_prefix_ok(const char *s)
{
    if (!s) return 0;
    size_t n = strlen(s);
    if (n < 8) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = (c >= '0' && c <= '9') ||
                 (c >= 'a' && c <= 'f') ||
                 (c >= 'A' && c <= 'F');
        if (!ok) return 0;
    }
    return 1;
}