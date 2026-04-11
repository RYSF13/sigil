#ifndef SIGIL_UTIL_H
#define SIGIL_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void     bin2hex(char *out, const uint8_t *in, size_t len);
int      hex2bin(uint8_t *out, size_t outlen, const char *hex);

char    *b64_encode(const uint8_t *in, size_t len);
int      b64_decode(uint8_t **out, size_t *outlen, const char *in);

int      read_file(const char *path, uint8_t **out, size_t *len);
int      write_file(const char *path, const uint8_t *data, size_t len);

int      read_all_stream(FILE *fp, uint8_t **out, size_t *len);
int      read_all_text(FILE *fp, char **out, size_t *len);

int      ensure_dir(const char *path);
void     sigil_dir(char *out, size_t len);

void     put_u16le(uint8_t *p, uint16_t v);
uint16_t get_u16le(const uint8_t *p);
void     put_u32le(uint8_t *p, uint32_t v);
uint32_t get_u32le(const uint8_t *p);

int      is_hex_prefix_ok(const char *s);

#endif