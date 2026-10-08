# ssh-agent-crypt

## ssh-agent is enough

Encrypt and decrypt with the SSH key you already have loaded.
No private key export. No extra key file. No sidecar secret store.
`ssh-agent` is already part of your daily flow. That is enough.

## Install / Quick Round-Trip

```bash
npm install -g ssh-agent-crypt

echo "ok" | ssh-agent-crypt | ssh-agent-crypt -decrypt
ok
```

## Usage

Encrypt with the first key loaded in your agent:

```bash
cat secret.txt | ssh-agent-crypt > secret.enc
```

Decrypt using the fingerprint embedded in the payload:

```bash
cat secret.enc | ssh-agent-crypt -decrypt > secret.txt
```

Pick a specific key from your agent by public key path, comment, SHA256 fingerprint, or MD5 fingerprint:

```bash
ssh-agent-crypt id_ed25519.pub < secret.txt > secret.enc
ssh-agent-crypt user@host < secret.txt > secret.enc
ssh-agent-crypt SHA256:abc123... < secret.txt > secret.enc
ssh-agent-crypt MD5:aa:bb:cc:dd:... < secret.txt > secret.enc
```

You can also use a direct private key file, with no need for an agent running.
Supported key algorithms still apply.

```bash
ssh-agent-crypt ~/.ssh/id_ed25519 < secret.txt > secret.enc
```

## What It Does

`ssh-agent-crypt` asks `ssh-agent` to sign a random salt through `ssh-keygen -Y sign`, derives two subkeys from that signature material, then uses:

- `AES-256-CBC` for encryption
- `HMAC-SHA256` for authentication

The output is one line:

```text
ssh-agent-crypt:v2:<fingerprint>.<salt_b64>.<iv_hex>.<ciphertext_b64>.<mac_hex>
```

The SHA256 fingerprint selects the signing key automatically, regardless of
agent key order, and is authenticated by the HMAC. An explicit key selector
still overrides automatic selection. Legacy v1 payloads remain readable using
the previous first-key/explicit-selector behavior.

## Supported Key Algorithms

- EdDSA (`ssh-ed25519`)
- RSA (`ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`)

ECDSA is not supported.

## Requirements

- `bash`
- `openssl`
- `ssh-agent`, `ssh-add`, `ssh-keygen`

## Tests

Bash and JavaScript are both canonical implementations of the same v2 format.
Tests verify encryption and decryption in both directions. The test harness
uses the local `ssh-agent-js` dev dependency.

```bash
npm test
```

## Credits

- [Francois Leurent/131](https://github.com/131)

## Node API

The asynchronous JavaScript API implements the same flow as Bash using Node
crypto and `ssh2` for agent access, key parsing and SSH signatures.
No subprocesses, Bash or OpenSSL:

```js
const {encrypt, decrypt} = require('ssh-agent-crypt');
const armored = await encrypt('secret');
const plaintext = await decrypt(armored);
```

Both functions accept an optional key selector and an environment override:
`encrypt(input, key, {env})`. Both return promises with UTF-8 output; failures reject.
