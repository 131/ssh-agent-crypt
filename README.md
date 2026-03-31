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

Decrypt with the same key:

```bash
cat secret.enc | ssh-agent-crypt -decrypt > secret.txt
```

Pick a specific `ssh-agent` identity by public key path, comment, SHA256 fingerprint, or MD5 fingerprint:

```bash
ssh-agent-crypt id_ed25519.pub < secret.txt > secret.enc
ssh-agent-crypt user@host < secret.txt > secret.enc
ssh-agent-crypt SHA256:abc123... < secret.txt > secret.enc
ssh-agent-crypt MD5:aa:bb:cc:dd:... < secret.txt > secret.enc
```

## What It Does

`ssh-agent-crypt` asks `ssh-agent` to sign a random salt through `ssh-keygen -Y sign`, derives two subkeys from that signature material, then uses:

- `AES-256-CBC` for encryption
- `HMAC-SHA256` for authentication

The output is one line:

```text
ssh-agent-crypt:v1:<salt_b64>.<iv_hex>.<ciphertext_b64>.<mac_hex>
```

## Supported Keys

- `ssh-ed25519`
- RSA (`ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`)

ECDSA is rejected by design: the signature output is not reproducible enough for this derivation scheme.

## Requirements

- `bash`
- `openssl`
- `ssh-agent`, `ssh-add`, `ssh-keygen`

## Tests

The shipped tool is pure bash. The test harness uses the local `ssh-agent-js` dev dependency.

```bash
npm test
```

## Credits

- [Francois Leurent/131](https://github.com/131)
