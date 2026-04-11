#ifndef SIGIL_KEYRING_H
#define SIGIL_KEYRING_H

#include "key.h"
#include <stddef.h>

int  keyring_init(void);

int  keyring_store_pub(const SigilPubKey *pub);
int  keyring_store_sec(const SigilSecKey *sec);

int  keyring_find_pub(SigilPubKey *pub, const char *fp_prefix_hex);
int  keyring_find_sec(SigilSecKey *sec, const char *fp_prefix_hex);

void keyring_list(int sec_only);
int  keyring_delete(const char *fp_prefix_hex);

/* config INI:
   [default]
   fingerprint = abcd1234ef567890
*/
int  keyring_get_default(char *out_prefix, size_t outlen);
int  keyring_set_default(const char *prefix);

int  keyring_pick_only_secret(char *out_prefix, size_t outlen);

#endif