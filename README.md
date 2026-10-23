# ssh-agent-crypt

## ssh-agent is enough

Encrypt and decrypt with the SSH key you already have loaded.
No private key export. No extra key file. No sidecar secret store.
`ssh-agent` is already part of your daily flow. That is enough.

## Install

Pick whichever fits the machine in front of you; all four speak the same format.

### npm

```bash
npm install -g ssh-agent-crypt
```

Installs the Node CLI (`bin/ssh-agent-crypt.js`) and the `ssh-agent-crypt`
module for your own code.

### Portable Bash

One file, no dependencies beyond `ssh-keygen` and `openssl`. Read it before
you run it; it is short.

```bash
curl -fsSL https://raw.githubusercontent.com/131/ssh-agent-crypt/master/bin/ssh-agent-crypt > ssh-agent-crypt
chmod +x ssh-agent-crypt
```

### Binary

Standalone, static, signed on Windows, with `SHA256SUMS` on every
[release](https://github.com/131/ssh-agent-crypt/releases).

```bash
# Linux
wget -O ssh-agent-crypt https://github.com/131/ssh-agent-crypt/releases/latest/download/ssh-agent-crypt-linux-amd64
chmod +x ssh-agent-crypt
```

```powershell
# Windows
Invoke-WebRequest https://github.com/131/ssh-agent-crypt/releases/latest/download/ssh-agent-crypt-windows-amd64.exe -OutFile ssh-agent-crypt.exe
```

### Go

```bash
go install github.com/131/ssh-agent-crypt/cmd/ssh-agent-crypt@latest
```

## Quick round-trip

```bash
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
first-key/explicit-selector behavior). Encryption always produces v3. The
namespace change means a routine `ssh-keygen -Y sign -n file` signature can
no longer double as key material for new ciphertexts; re-encrypt v2 data to
get that property.

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

## Requirements

Bash CLI:

- `bash`
- `openssl`
- `ssh-agent`, `ssh-add`, `ssh-keygen`

Node and Go implementations only need a reachable agent at `SSH_AUTH_SOCK`
(Unix socket, or a Windows named pipe such as `\\.\pipe\openssh-ssh-agent`).
On Windows without `SSH_AUTH_SOCK`, the Go implementation connects to the
running Pageant (0.75 or later, whose named pipe is derived the way PuTTY
does it), and falls back to the Windows OpenSSH agent pipe; the Node
implementation uses the legacy Pageant window protocol.

## Tests

Bash, JavaScript and Go are canonical implementations of the same v3 format.
Tests verify encryption and decryption in every direction. The Node harness
uses the local `ssh-agent-js` dev dependency and exercises the Go CLI when
`go` is on `PATH`; the Go tests spawn a throwaway `ssh-agent` and cross-check
against the Bash CLI and, when `node_modules` is installed, the Node API.
`test/fixtures/` pins the formats: throwaway keys with v1, v2 and v3 armors
of `legacy token`, which every implementation must keep reading.

```bash
npm test
go test ./...
```

## Credits

- [Francois Leurent/131](https://github.com/131)
- [OpenAI](https://openai.com) Codex (GPT 6.1-sol), in collaboration
- [Anthropic](https://www.anthropic.com) Claude (Fable 5.1), in collaboration

## Node API

The asynchronous JavaScript API implements the same flow as Bash using Node
crypto and `ssh2` for agent access, key parsing and SSH signatures.
No subprocesses, Bash or OpenSSL:

```js
const {encrypt, decrypt} = require('ssh-agent-crypt');
const armored = await encrypt('secret');
const plaintext = (await decrypt(armored)).toString();
```

Both functions accept an optional key selector and an environment override:
`encrypt(input, key, {env})` (`env.SSH_AUTH_SOCK`, `env.SSH_AGENT_CRYPT_KEY` and the
`VAUTH_USER_*` fallbacks are read from it). `encrypt` takes a string or a `Buffer` and
resolves to the armored line; `decrypt` resolves to the plaintext as a
`Buffer`. Failures reject.

## Go API and CLI

The Go module shares the repository tag with the npm package
(`github.com/131/ssh-agent-crypt@vX.Y.Z`). It uses `golang.org/x/crypto/ssh`
for agent access, key parsing and SSH signatures, no subprocesses:

```go
import sshagentcrypt "github.com/131/ssh-agent-crypt"

armored, err := sshagentcrypt.Encrypt([]byte("secret"), "", nil)
plaintext, err := sshagentcrypt.Decrypt([]byte(armored), "", nil)
```

Both functions accept the same key selector as the CLI and an optional
`*Options` (`AgentSocket` overrides `DefaultAgentAddress()`, `DefaultKey`
overrides `SSH_AGENT_CRYPT_KEY`, `Rand` the entropy source). `Decrypt` returns the raw bytes. `DefaultAgentAddress`,
`DialAgent` and, on Windows, `PageantPipeName` are exported for programs
sharing the agent transport.

The Go CLI mirrors the Bash one; it is the binary attached to releases.

## Security audit

Two independent reviews of the design and of the three implementations, each
scoring Coolness, Robustness and Safety out of 20:
[SECURITY_AUDIT_fable-5.1.md](SECURITY_AUDIT_fable-5.1.md) and
[SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).

| Criterion | Codex (Claude Fable 5.1) | Codex (GPT 6.1) |
| --- | ---: | ---: |
| Coolness | 16/20 | 18/20 |
| Robustness | 16/20 | 16/20 |
| Safety | 14/20 | 15/20 |
