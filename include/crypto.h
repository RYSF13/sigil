#ifndef SIGIL_CRYPTO_H
#define SIGIL_CRYPTO_H

#include "key.h"

int crypto_encrypt_to(const SigilPubKey *recipient);
int crypto_decrypt_with(const SigilSecKey *sec);

#endif