#ifndef SIGIL_CERTIFY_H
#define SIGIL_CERTIFY_H

#include "key.h"

int certify_key(const SigilPubKey *target, const SigilSecKey *my_sec);
int certify_check(const SigilPubKey *target);

#endif