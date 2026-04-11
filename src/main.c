#include "cli.h"
#include <sodium.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sigil: libsodium init failed\n");
        return 1;
    }
    return cli_run(argc, argv);
}