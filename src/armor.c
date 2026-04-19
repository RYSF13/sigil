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

void armor_print_sec(const SigilSecKey *sec)
{
    uint8_t *bin; size_t len;
    if (key_sec_serialize(sec, &bin, &len) != 0) return;

    char *b64 = b64_encode(bin, len);
    free(bin);
    if (!b64) return;

    printf("%-32s %s\n", sec->name, sec->mail);
    printf("SigilPRI %s\n", b64);
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

int armor_parse(uint8_t **data, size_t *len)
{
    uint8_t *src, *decoded;
    size_t srclen, tail_len, decoded_len, b64len;
    uint8_t *nl, *line2, *line2_end;
    char *b64 = NULL;

    if (!data || !*data || !len) return -1;

    src = *data;
    srclen = *len;

    nl = memchr(src, '\n', srclen);
    if (!nl) return -1;
    line2 = nl + 1;
    tail_len = srclen - (size_t)(line2 - src);

    while (tail_len > 0 && (*line2 == '\r' || *line2 == '\n')) {
        line2++;
        tail_len--;
    }

    if (tail_len < 9) return -1;

    if (memcmp(line2, "SigilPUB ", 9) != 0 &&
        memcmp(line2, "SigilPRI ", 9) != 0) {
        return -1;
    }

    line2 += 9;
    tail_len -= 9;

    line2_end = memchr(line2, '\n', tail_len);
    if (!line2_end) line2_end = line2 + tail_len;

    while (line2_end > line2 &&
           (line2_end[-1] == '\r' ||
            line2_end[-1] == ' ' ||
            line2_end[-1] == '\t')) {
        line2_end--;
    }

    b64len = (size_t)(line2_end - line2);
    if (b64len == 0) return -1;

    b64 = (char *)malloc(b64len + 1);
    if (!b64) return -1;

    memcpy(b64, line2, b64len);
    b64[b64len] = '\0';

    if (b64_decode(&decoded, &decoded_len, b64) != 0) {
        free(b64);
        return -1;
    }
    free(b64);

    if (decoded_len < 8 ||
        (memcmp(decoded, SIGIL_PUB_MAGIC, 8) != 0 &&
         memcmp(decoded, SIGIL_PRI_MAGIC, 8) != 0)) {
        free(decoded);
        return -1;
    }

    free(*data);
    *data = decoded;
    *len = decoded_len;
    return 0;
}