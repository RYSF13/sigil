#ifndef SIGIL_SIGN_H
#define SIGIL_SIGN_H

#include "key.h"

int sigil_sign(const SigilSecKey *sec);
int sigil_verify(const SigilPubKey *maybe_pub /* optional, can be NULL */);

#endif