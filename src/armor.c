#include "armor.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void armor_print_pub(const SigilPubKey *pub)
{
    uint8_t *bin; size_t len;
    if (key_pub_serialize(pub, &bin, &len) != 0) return;

    char *b64 = b64_encode(bin, len);
    free(bin);
    if (!b64) return;

    printf("%-32s %s\n", pub->name, pub->mail);
    printf("SigilPUB %s\n", b64);
    free(b64);
}

void armor_wrap(const char *type, const uint8_t *data, size_t len)
{
    char *b64 = b64_encode(data, len);
    if (!b64) return;

    printf("-----BEGIN SIGIL %s-----\n", type);
    printf("Version: 1\n\n");
    printf("%s\n", b64);
    printf("-----END SIGIL %s-----\n", type);

    free(b64);
}

static char *extract_b64_block(const char *type, const char *text)
{
    char begin[64], end[64];
    snprintf(begin, sizeof begin, "-----BEGIN SIGIL %s-----", type);
    snprintf(end, sizeof end, "-----END SIGIL %s-----", type);

    const char *b = strstr(text, begin);
    if (!b) return NULL;

    const char *p = strstr(b, "\n\n");
    if (!p) return NULL;
    p += 2;

    const char *e = strstr(p, end);
    if (!e) return NULL;

    size_t n = (size_t)(e - p);
    while (n > 0 && (p[n-1] == '\n' || p[n-1] == '\r')) n--;

    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, p, n);
    out[n] = 0;
    return out;
}

int armor_unwrap(const char *type, const char *text, uint8_t **out, size_t *len)
{
    char *b64 = extract_b64_block(type, text);
    if (!b64) return -1;

    int r = b64_decode(out, len, b64);
    free(b64);
    return r;
}