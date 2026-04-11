#ifndef SIGIL_KEY_H
#define SIGIL_KEY_H

#include <stdint.h>
#include <stddef.h>

#define SIGIL_PUB_MAGIC "SigilPUB"
#define SIGIL_PRI_MAGIC "SigilPRI"
#define SIGIL_MSG_MAGIC "SigilMSG"
#define SIGIL_SIG_MAGIC "SigilSIG"
#define SIGIL_CSG_MAGIC "SigilCSG"

#define SIGIL_VERSION   0x01
#define SIGIL_ALG_25519 0x01

#define FP_LEN 32

typedef struct {
    uint8_t  enc_pub[32];   /* X25519 public */
    uint8_t  sig_pub[32];   /* Ed25519 public */
    uint8_t  fp[FP_LEN];    /* BLAKE2b-256 */
    char    *name;          /* heap */
    char    *mail;          /* heap */
    uint32_t created;
} SigilPubKey;

typedef struct {
    uint8_t  encrypted;     /* 0/1 */
    uint8_t  fp[FP_LEN];

    char    *name;          /* heap */
    char    *mail;          /* heap */
    uint32_t created;

    uint8_t  salt[16];
    uint8_t  nonce[24];

    uint8_t  enc_sec[32];   /* X25519 secret */
    uint8_t  sig_sec[64];   /* Ed25519 secret */


    uint8_t  encseckey[96];
} SigilSecKey;

void key_free_pub(SigilPubKey *k);
void key_free_sec(SigilSecKey *k);

void key_fingerprint(uint8_t fp[32],
                     const uint8_t enc_pub[32],
                     const uint8_t sig_pub[32],
                     const char *name, const char *mail);

void fp_to_hex(char out[65], const uint8_t fp[32]);

int  key_generate(SigilPubKey *pub, SigilSecKey *sec,
                  const char *name, const char *mail);

int  key_pub_serialize(const SigilPubKey *pub, uint8_t **out, size_t *len);
int  key_pub_parse(SigilPubKey *pub, const uint8_t *data, size_t len);

int  key_sec_serialize(const SigilSecKey *sec, uint8_t **out, size_t *len);
int  key_sec_parse(SigilSecKey *sec, const uint8_t *data, size_t len);

int  key_sec_encrypt(SigilSecKey *sec, const char *pass);
int  key_sec_decrypt(SigilSecKey *sec, const char *pass);

int  key_sec_selfcheck_plain(const SigilSecKey *sec);

#endif