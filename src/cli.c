#include "cli.h"
#include "key.h"
#include "keyring.h"
#include "armor.h"
#include "crypto.h"
#include "sign.h"
#include "certify.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>

static void usage(void)
{
    fprintf(stderr,
        "Usage: sigil <command> [options]\n"
        "\n"
        "Commands:\n"
        "  gen --name NAME --mail MAIL [--curve 25519]\n"
        "  list [--sec]\n"
        "  show <fingerprint>\n"
        "  delete <fingerprint>\n"
        "  import <file>\n"
        "  export-pub <fingerprint>\n"
        "  export-sec <fingerprint>\n"
        "  encrypt --to <fingerprint>\n"
        "  decrypt [--from <fingerprint>]\n"
        "  sign --from <fingerprint>\n"
        "  verify [--from <fingerprint>]\n"
        "  certify --target <fingerprint> --from <fingerprint>\n"
        "  check-sigs <fingerprint>\n"
        "  fingerprint <fingerprint>\n"
    );
}

static const char *get_opt(int argc, char **argv, const char *key)
{
    size_t k = strlen(key);
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], key, k) == 0) {
            if (argv[i][k] == '=')
                return argv[i] + k + 1;
            if (argv[i][k] == 0 && i + 1 < argc)
                return argv[i + 1];
        }
    }
    return NULL;
}

static int has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], flag) == 0) return 1;
    return 0;
}


static int read_pass(char *out, size_t n, const char *prompt)
{
    struct termios oldt, newt;
    FILE *tty = fopen("/dev/tty", "r+");
    
    if (!tty) {
        fprintf(stderr, "sigil: cannot open /dev/tty for passphrase prompt\n");
        return -1;
    }

    fprintf(tty, "%s", prompt);
    fflush(tty);

    int fd = fileno(tty);
    if (tcgetattr(fd, &oldt) != 0) {
        fclose(tty);
        return -1;
    }
    
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(fd, TCSANOW, &newt) != 0) {
        fclose(tty);
        return -1;
    }

    if (!fgets(out, (int)n, tty)) out[0] = 0;
    out[strcspn(out, "\r\n")] = 0;

    tcsetattr(fd, TCSANOW, &oldt);
    fprintf(tty, "\n");
    fclose(tty);
    return 0;
}

static void fmt_date(uint32_t ts, char out[16])
{
    time_t t = (time_t)ts;
    struct tm *tm = localtime(&t);
    if (!tm) { snprintf(out, 16, "%u", ts); return; }
    snprintf(out, 16, "%04d-%02d-%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
}

static void fmt_fp_grouped(const char fphex[65], char out[100])
{
    /* 64 hex -> groups of 4 with spaces */
    size_t j = 0;
    for (int i = 0; i < 64; i++) {
        out[j++] = fphex[i];
        if ((i % 4) == 3 && i != 63) out[j++] = ' ';
    }
    out[j] = 0;
}

/* --- commands --- */

static int cmd_gen(int argc, char **argv)
{
    const char *name = get_opt(argc, argv, "--name");
    const char *mail = get_opt(argc, argv, "--mail");
    if (!name || !mail) {
        fprintf(stderr, "sigil gen: --name and --mail required\n");
        return 1;
    }

    SigilPubKey pub;
    SigilSecKey sec;
    if (key_generate(&pub, &sec, name, mail) != 0) {
        fprintf(stderr, "sigil: key generation failed\n");
        return 1;
    }

    char pass1[256], pass2[256];
    if (read_pass(pass1, sizeof pass1, "Passphrase for private key (empty = none): ") != 0)
        return 1;
    if (strlen(pass1) > 0) {
        if (read_pass(pass2, sizeof pass2, "Confirm passphrase: ") != 0)
            return 1;
        if (strcmp(pass1, pass2) != 0) {
            fprintf(stderr, "sigil: passphrase mismatch\n");
            key_free_pub(&pub);
            key_free_sec(&sec);
            return 1;
        }
        if (key_sec_encrypt(&sec, pass1) != 0) {
            fprintf(stderr, "sigil: failed to encrypt private key\n");
            key_free_pub(&pub);
            key_free_sec(&sec);
            return 1;
        }
    }

    if (keyring_store_pub(&pub) != 0 || keyring_store_sec(&sec) != 0) {
        fprintf(stderr, "sigil: failed to store key\n");
        key_free_pub(&pub);
        key_free_sec(&sec);
        return 1;
    }

    char fphex[65]; fp_to_hex(fphex, pub.fp);
    printf("Generated: %s <%s>\n", pub.name, pub.mail);
    printf("Fingerprint: %.16s\n", fphex);

    char def[128];
    if (keyring_get_default(def, sizeof def) != 0) {
        keyring_set_default(fphex); 
    }

    key_free_pub(&pub);
    key_free_sec(&sec);
    return 0;
}

static int cmd_list(int argc, char **argv)
{
    keyring_list(has_flag(argc, argv, "--sec"));
    return 0;
}

static int cmd_show(const char *fp)
{
    SigilPubKey pub;
    if (keyring_find_pub(&pub, fp) != 0) {
        fprintf(stderr, "sigil: key not found or ambiguous: %s\n", fp);
        return 1;
    }

    char fphex[65]; fp_to_hex(fphex, pub.fp);
    char fpgrp[100]; fmt_fp_grouped(fphex, fpgrp);

    char date[16]; fmt_date(pub.created, date);

    printf("Name:        %s\n", pub.name);
    printf("Mail:        %s\n", pub.mail);
    printf("Algorithm:   X25519 + Ed25519\n");
    printf("Created:     %s\n", date);
    printf("Fingerprint: %s\n", fpgrp);

    key_free_pub(&pub);
    return 0;
}

static int cmd_delete(const char *fp)
{
    printf("Delete key %s? [y/N] ", fp);
    fflush(stdout); 

    char buf[16];

    FILE *tty = fopen("/dev/tty", "r");
    FILE *in = tty ? tty : stdin;

    if (!fgets(buf, sizeof(buf), in)) {
        buf[0] = 0;
    }
    if (tty) fclose(tty);

    if (buf[0] != 'y' && buf[0] != 'Y') {
        printf("Aborted.\n");
        return 0;
    }
    if (keyring_delete(fp) != 0) {
        fprintf(stderr, "sigil: delete failed\n");
        return 1;
    }
    printf("Deleted.\n");
    return 0;
}

static int cmd_import(const char *file)
{
    uint8_t *data; size_t len;
    if (read_file(file, &data, &len) != 0) {
        fprintf(stderr, "sigil: cannot read file\n");
        return 1;
    }

    if (!(len >= 8 &&
          (memcmp(data, SIGIL_PUB_MAGIC, 8) == 0 ||
           memcmp(data, SIGIL_PRI_MAGIC, 8) == 0))) {
        armor_parse(&data, &len);
    }

    if (len >= 8 && memcmp(data, SIGIL_PUB_MAGIC, 8) == 0) {
        SigilPubKey pub;
        if (key_pub_parse(&pub, data, len) != 0) { free(data); return 2; }
        if (keyring_store_pub(&pub) != 0) { key_free_pub(&pub); free(data); return 1; }
        char fphex[65]; fp_to_hex(fphex, pub.fp);
        printf("Imported: %.16s\n", fphex);
        key_free_pub(&pub);
        free(data);
        return 0;
    }

    if (len >= 8 && memcmp(data, SIGIL_PRI_MAGIC, 8) == 0) {
        SigilSecKey sec;
        if (key_sec_parse(&sec, data, len) != 0) { free(data); return 2; }
        if (keyring_store_sec(&sec) != 0) { key_free_sec(&sec); free(data); return 1; }
        char fphex[65]; fp_to_hex(fphex, sec.fp);
        printf("Imported: %.16s\n", fphex);
        key_free_sec(&sec);
        free(data);
        return 0;
    }

    free(data);
    fprintf(stderr, "sigil: unknown file format\n");
    return 2;
}

static int cmd_export_pub(const char *fp)
{
    SigilPubKey pub;
    if (keyring_find_pub(&pub, fp) != 0) {
        fprintf(stderr, "sigil: public key not found or ambiguous\n");
        return 1;
    }
    armor_print_pub(&pub);
    key_free_pub(&pub);
    return 0;
}

static int cmd_export_sec(const char *fp)
{
    SigilSecKey sec;
    if (keyring_find_sec(&sec, fp) != 0) {
        fprintf(stderr, "sigil: private key not found or ambiguous\n");
        return 1;
    }
    armor_print_sec(&sec);
    key_free_sec(&sec);
    return 0;
}

static int cmd_encrypt(int argc, char **argv)
{
    const char *to = get_opt(argc, argv, "--to");
    if (!to) {
        fprintf(stderr, "sigil encrypt: --to required\n");
        return 1;
    }

    SigilPubKey pub;
    if (keyring_find_pub(&pub, to) != 0) {
        fprintf(stderr, "sigil: recipient key not found or ambiguous\n");
        return 1;
    }

    int r = crypto_encrypt_to(&pub);
    key_free_pub(&pub);
    return r;
}

static int cmd_decrypt(int argc, char **argv)
{
    const char *from = get_opt(argc, argv, "--from");

    char chosen[128] = {0};
    if (from) {
        strncpy(chosen, from, sizeof chosen - 1);
    } else {
        if (keyring_get_default(chosen, sizeof chosen) != 0) {
            if (keyring_pick_only_secret(chosen, sizeof chosen) != 0) {
                fprintf(stderr, "sigil: no --from and no default/unique private key\n");
                return 1;
            }
        }
    }

    SigilSecKey sec;
    if (keyring_find_sec(&sec, chosen) != 0) {
        fprintf(stderr, "sigil: private key not found or ambiguous\n");
        return 1;
    }

    if (sec.encrypted) {
        char pass[256];
        if (read_pass(pass, sizeof pass, "Passphrase: ") != 0) { key_free_sec(&sec); return 1; }
        if (key_sec_decrypt(&sec, pass) != 0) {
            fprintf(stderr, "sigil: wrong passphrase or corrupted key\n");
            key_free_sec(&sec);
            return 2;
        }
    }

    int r = crypto_decrypt_with(&sec);
    key_free_sec(&sec);
    return r;
}

static int cmd_sign(int argc, char **argv)
{
    const char *from = get_opt(argc, argv, "--from");
    if (!from) {
        fprintf(stderr, "sigil sign: --from required\n");
        return 1;
    }

    SigilSecKey sec;
    if (keyring_find_sec(&sec, from) != 0) {
        fprintf(stderr, "sigil: private key not found or ambiguous\n");
        return 1;
    }

    if (sec.encrypted) {
        char pass[256];
        if (read_pass(pass, sizeof pass, "Passphrase: ") != 0) { key_free_sec(&sec); return 1; }
        if (key_sec_decrypt(&sec, pass) != 0) {
            fprintf(stderr, "sigil: wrong passphrase or corrupted key\n");
            key_free_sec(&sec);
            return 2;
        }
    }

    int r = sigil_sign(&sec);
    key_free_sec(&sec);
    return r;
}

static int cmd_verify(int argc, char **argv)
{
    const char *from = get_opt(argc, argv, "--from");
    if (!from) {
        return sigil_verify(NULL);
    }

    SigilPubKey pub;
    if (keyring_find_pub(&pub, from) != 0) {
        fprintf(stderr, "sigil: public key not found or ambiguous\n");
        return 1;
    }
    int r = sigil_verify(&pub);
    key_free_pub(&pub);
    return r;
}

static int cmd_certify(int argc, char **argv)
{
    const char *target = get_opt(argc, argv, "--target");
    const char *from   = get_opt(argc, argv, "--from");
    if (!target || !from) {
        fprintf(stderr, "sigil certify: --target and --from required\n");
        return 1;
    }

    SigilPubKey target_pub;
    if (keyring_find_pub(&target_pub, target) != 0) {
        fprintf(stderr, "sigil: target public key not found or ambiguous\n");
        return 1;
    }

    SigilSecKey my_sec;
    if (keyring_find_sec(&my_sec, from) != 0) {
        fprintf(stderr, "sigil: your private key not found or ambiguous\n");
        key_free_pub(&target_pub);
        return 1;
    }

    if (my_sec.encrypted) {
        char pass[256];
        if (read_pass(pass, sizeof pass, "Passphrase: ") != 0) { key_free_pub(&target_pub); key_free_sec(&my_sec); return 1; }
        if (key_sec_decrypt(&my_sec, pass) != 0) {
            fprintf(stderr, "sigil: wrong passphrase or corrupted key\n");
            key_free_pub(&target_pub);
            key_free_sec(&my_sec);
            return 2;
        }
    }

    int r = certify_key(&target_pub, &my_sec);
    key_free_pub(&target_pub);
    key_free_sec(&my_sec);
    return r;
}

static int cmd_check_sigs(const char *fp)
{
    SigilPubKey pub;
    if (keyring_find_pub(&pub, fp) != 0) {
        fprintf(stderr, "sigil: public key not found or ambiguous\n");
        return 1;
    }
    int r = certify_check(&pub);
    key_free_pub(&pub);
    return r;
}

int cli_run(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];
    int subc = argc - 2;
    char **subv = argv + 2;

    if (strcmp(cmd, "gen") == 0) return cmd_gen(subc, subv);
    if (strcmp(cmd, "list") == 0) return cmd_list(subc, subv);

    if (strcmp(cmd, "show") == 0) {
        if (subc < 1) { fprintf(stderr, "sigil show: fingerprint required\n"); return 1; }
        return cmd_show(subv[0]);
    }

    if (strcmp(cmd, "fingerprint") == 0) {
        if (subc < 1) { fprintf(stderr, "sigil fingerprint: fingerprint required\n"); return 1; }
        return cmd_show(subv[0]);
    }

    if (strcmp(cmd, "delete") == 0) {
        if (subc < 1) { fprintf(stderr, "sigil delete: fingerprint required\n"); return 1; }
        return cmd_delete(subv[0]);
    }

    if (strcmp(cmd, "import") == 0) {
        if (subc < 1) { fprintf(stderr, "sigil import: file required\n"); return 1; }
        return cmd_import(subv[0]);
    }

    if (strcmp(cmd, "export-pub") == 0) {
        if (subc < 1) { fprintf(stderr, "sigil export-pub: fingerprint required\n"); return 1; }
        return cmd_export_pub(subv[0]);
    }

    if (strcmp(cmd, "export-sec") == 0) {
        if (subc < 1) { fprintf(stderr, "sigil export-sec: fingerprint required\n"); return 1; }
        return cmd_export_sec(subv[0]);
    }

    if (strcmp(cmd, "encrypt") == 0) return cmd_encrypt(subc, subv);
    if (strcmp(cmd, "decrypt") == 0) return cmd_decrypt(subc, subv);
    if (strcmp(cmd, "sign") == 0) return cmd_sign(subc, subv);
    if (strcmp(cmd, "verify") == 0) return cmd_verify(subc, subv);

    if (strcmp(cmd, "certify") == 0) return cmd_certify(subc, subv);

    if (strcmp(cmd, "check-sigs") == 0) {
        if (subc < 1) { fprintf(stderr, "sigil check-sigs: fingerprint required\n"); return 1; }
        return cmd_check_sigs(subv[0]);
    }

    fprintf(stderr, "sigil: unknown command '%s'\n", cmd);
    usage();
    return 1;
}