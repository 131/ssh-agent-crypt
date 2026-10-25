# ssh-agent-crypt

## ssh-agent is enough

Encrypt and decrypt with the SSH key you already have loaded.
No private key export. No extra key file. No sidecar secret store.
`ssh-agent` is already part of your daily flow. That is enough.

## Quick round-trip

```bash
echo "ok" | ssh-agent-crypt | ssh-agent-crypt -decrypt
ok
```

## Install

Pick whichever fits the machine in front of you; all four speak the same format.

```bash
# node
npm install -g ssh-agent-crypt

# portable bash (one file, needs ssh-keygen and openssl; read it, it is short)
curl -fsSL https://raw.githubusercontent.com/131/ssh-agent-crypt/master/bin/ssh-agent-crypt > ssh-agent-crypt
chmod +x ssh-agent-crypt

# go
go install github.com/131/ssh-agent-crypt/cmd/ssh-agent-crypt@latest

# static binary, linux
wget -O ssh-agent-crypt https://github.com/131/ssh-agent-crypt/releases/latest/download/ssh-agent-crypt-linux-amd64
chmod +x ssh-agent-crypt

# static binary, windows (curl.exe ships with every supported Windows, cmd or PowerShell)
curl.exe -fsSL -o ssh-agent-crypt.exe https://github.com/131/ssh-agent-crypt/releases/latest/download/ssh-agent-crypt-windows-amd64.exe
```

The [npm](https://www.npmjs.com/package/ssh-agent-crypt) package carries the Node CLI, the [Bash script](bin/ssh-agent-crypt)
and the `ssh-agent-crypt` module. Binaries are static, signed on Windows, with
`SHA256SUMS` on every [release](https://github.com/131/ssh-agent-crypt/releases).
On Windows the agent is `SSH_AUTH_SOCK` when set, else a running Pageant
(0.75+), else the OpenSSH agent pipe.

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

Or set the key once for the shell; `SSH_AGENT_CRYPT_KEY` takes the same
values as the argument and stands in for it when omitted (then
`VAUTH_USER_IDENTITY` and `VAUTH_USER_MAIL`, for shells provisioned by
vauth). When decrypting a payload that carries a fingerprint, the fingerprint
still wins, so you keep reading anything addressed to any key in your agent:

```bash
export SSH_AGENT_CRYPT_KEY=user@host
ssh-agent-crypt < secret.txt > secret.enc
```

You can also use a direct private key file, with no need for an agent running.
Supported key algorithms still apply.

```bash
ssh-agent-crypt ~/.ssh/id_ed25519 < secret.txt > secret.enc
```

## What It Does

`ssh-agent-crypt` asks `ssh-agent` to sign a random salt in the dedicated
SSHSIG namespace `ssh-agent-crypt` (what `ssh-keygen -Y sign -n
ssh-agent-crypt` produces), derives two subkeys from that signature material,
then uses:

- `AES-256-CBC` for encryption
- `HMAC-SHA256` for authentication

The output is one line:

```text
ssh-agent-crypt:v3:<fingerprint>.<salt_b64>.<iv_hex>.<ciphertext_b64>.<mac_hex>
```

The SHA256 fingerprint selects the signing key automatically, regardless of
agent key order. The HMAC covers the header and every field before it, so
the format version, the key fingerprint, the salt, the IV and the ciphertext
are all authenticated. An explicit key selector still overrides automatic
selection.

Legacy payloads remain readable: v2 (same layout, signed in the generic
`file` namespace, header not authenticated) and v1 (no fingerprint,
first-key/explicit-selector behavior). Encryption always produces v3.

Since the key material is a signature, whoever can ask your agent to sign can
also decrypt. Loading the key with `ssh-add -c` makes the agent ask for
confirmation on every use, including every `ssh-agent-crypt` call, and keeps
forwarded agents and background processes from deriving keys silently
(OpenSSH agent only; the Windows agents do not support it).

None of this is specific to `ssh-agent-crypt`: whoever reaches your
`SSH_AUTH_SOCK` already acts as you on every host that trusts those keys (a
GitLab instance will mint a personal access token over SSH, for instance).
Protecting the agent socket matters as much as protecting the keys it holds.

## Supported Key Algorithms

- EdDSA (`ssh-ed25519`)
- RSA (`ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`)

ECDSA is not supported.

## API & SDK

Node module, Go module, agent transport details and the test matrix:
[API_and_tests.md](API_and_tests.md).

## Security audit

Two independent reviews of the design and of the three implementations, each
scoring Coolness, Robustness and Safety out of 20:
[SECURITY_AUDIT_fable-5.1.md](SECURITY_AUDIT_fable-5.1.md) and
[SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).

| Criterion | Codex (Claude Fable 5.1) | Codex (GPT 6.1) |
| --- | ---: | ---: |
| ✨ **Coolness** | 16/20 | 18/20 |
| Robustness | 16/20 | 16/20 |
| Safety | 14/20 | 15/20 |

## Credits

- [Francois Leurent/131](https://github.com/131)
- [OpenAI](https://openai.com) Codex (GPT 6.1-sol), in collaboration
- [Anthropic](https://www.anthropic.com) Claude (Fable 5.1), in collaboration
- Code signing, courtesy of Essilor International
