# Sigil

Sigil is a small, practical command-line tool for public-key encryption and signing.  
It is designed to be lightweight, easy to use, and friendly to copy/paste workflows (email, chat, terminals).

Sigil uses modern elliptic-curve cryptography via **libsodium** and follows a “do one thing well” UNIX-style approach: it reads from **stdin**, writes to **stdout**, and composes well with pipes and redirection.

## Features

- Compact public keys (easy to share)
- Key generation and local keyring management
- Public-key encryption / decryption
- Signing / signature verification
- Key certification (sign a public key, then verify certifications)
- ASCII armor for messages and signatures
- Fingerprints for identifying keys

## Cryptography (v1)

Sigil v1 is built on libsodium primitives:

- Key exchange / encryption: **X25519**
- Signatures: **Ed25519**
- Symmetric encryption: **XChaCha20-Poly1305**
- Fingerprints: **BLAKE2b-256**
- Private-key protection: **Argon2id** + **XChaCha20-Poly1305**

No custom cryptographic algorithms are implemented.

## Installation

### Dependencies

- C toolchain (e.g. `gcc` or `clang`)
- `libsodium` development headers and library

On Debian/Ubuntu:

```bash
sudo apt-get install libsodium-dev
```

On Arch:

```bash
sudo pacman -S libsodium
```

### Build

```bash
make all
```

The Makefile links against libsodium (`-lsodium`) and uses `-O2`.  
It also attempts to strip the binary with `-s` (if your toolchain does not support it, remove `-s` from `LDFLAGS`).

## Quick start

### 1) Generate a keypair

```bash
./sigil gen --name "John Doe" --mail "john.doe@example.com"
```

You will be prompted for a passphrase. An empty passphrase leaves the private key unencrypted.

Keys are stored in your keyring:

```
~/.sigil/
    public/
    private/
    certs/
    config
```

### 2) List keys

```bash
./sigil list
./sigil list --sec
```

### 3) Show key details / fingerprint

```bash
./sigil show <fingerprint-prefix>
./sigil fingerprint <fingerprint-prefix>
```

You can use a fingerprint **prefix** (minimum 8 hex characters) as long as it is unambiguous.

### 4) Export a public key (share it)

```bash
./sigil export-pub <fingerprint-prefix> > someone.pub
```

This prints Sigil’s compact public key armor format (two lines). The output is intended to be easy to paste into emails or chat.

### 5) Import a key

```bash
./sigil import someone.pub
```

Sigil can import binary key files (`SigilPUB` / `SigilPRI`) as well.

### 6) Encrypt / decrypt

Encrypt (reads plaintext from stdin, outputs armored message to stdout):

```bash
echo "hello" | ./sigil encrypt --to <recipient-fp-prefix> > message.asc

# also can use 'cat' to read from a file
cat msg.txt | ./sigil encrypt --to <recipient-fp-prefix> > message.asc
```

Decrypt:

```bash
./sigil decrypt < message.asc
```

If you have multiple private keys, specify which one to use:

```bash
./sigil decrypt --from <my-fp-prefix> < message.asc
```

Sigil also supports a default key in `~/.sigil/config`. If no `--from` is provided, Sigil will try:
1) the configured default key, or
2) a single available private key (if there is exactly one).

### 7) Sign / verify

Sign (reads data from stdin; outputs an armored signature package):

```bash
echo "data" | ./sigil sign --from <my-fp-prefix> > data.sig
```

Verify:

```bash
./sigil verify < data.sig
```

You may also force a specific signer key (by fingerprint prefix):

```bash
./sigil verify --from <signer-fp-prefix> < data.sig
```

### 8) Certify (sign someone’s public key)

Certify a target public key (i.e. “I attest this key belongs to this person”):

```bash
./sigil certify --target <target-fp-prefix> --from <my-fp-prefix>
```

Check certifications on a key:

```bash
./sigil check-sigs <target-fp-prefix>
```

Certifications are stored under:

```
~/.sigil/certs/
```

## Command reference

```text
sigil gen --name NAME --mail MAIL [--curve 25519]
sigil list [--sec]
sigil show <fingerprint>
sigil delete <fingerprint>

sigil import <file>
sigil export-pub <fingerprint>
sigil export-sec <fingerprint>

sigil encrypt --to <fingerprint>
sigil decrypt [--from <fingerprint>]

sigil sign --from <fingerprint>
sigil verify [--from <fingerprint>]

sigil certify --target <fingerprint> --from <fingerprint>
sigil check-sigs <fingerprint>

sigil fingerprint <fingerprint>
```

Notes:

- Most commands use **stdin/stdout** by default.
- Fingerprint prefixes must be at least **8 hex chars**.
- Errors go to **stderr** so stdout remains clean for pipes/redirection.

## ASCII armor formats (v1)

### Public keys

Public keys use a compact two-line format:

```
<Name><padding><Email>
SigilPUB <base64>
```

The base64 payload is the binary `SigilPUB` structure.

### Encrypted messages

Messages are wrapped as:

```
-----BEGIN SIGIL MESSAGE-----
Version: 1

<base64>
-----END SIGIL MESSAGE-----
```

### Signatures

Signatures are wrapped as:

```
-----BEGIN SIGIL SIGNATURE-----
Version: 1

<base64>
-----END SIGIL SIGNATURE-----
```

## My public key

If you want to send me encrypted messages or verify signatures, here is my Sigil public key:

```
Robert Yates Stanford            rysf13@qq.com
SigilPUB U2lnaWxQVUIBAZlPGHkE+8eOi/viswbG4H13aXiI5fqjWSvO4s5L8uw6UOK87TB8BHp2rKbGDME8Sy04BVaw4H7hFr0KjsxM3uk2WSmKcvhjTWTITV89kd0Jej1z+07dhhBXNA+dXnvPbhVSb2JlcnQgWWF0ZXMgU3RhbmZvcmQNcnlzZjEzQHFxLmNvbVf72WkAAA==
```

## Security notes

- Sigil relies on libsodium. Keep it up to date.
- Do not reuse passphrases and consider using a password manager.
- Always verify fingerprints out-of-band when exchanging keys.

## License

MIT License. See `LICENSE`.