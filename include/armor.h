#ifndef SIGIL_ARMOR_H
#define SIGIL_ARMOR_H

#include "key.h"
#include <stddef.h>
#include <stdint.h>

void armor_print_pub(const SigilPubKey *pub);

/* MESSAGE / SIGNATURE armor */
void armor_wrap(const char *type, const uint8_t *data, size_t len);
int  armor_unwrap(const char *type, const char *text, uint8_t **out, size_t *len);

#endif