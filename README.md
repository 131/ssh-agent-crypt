# ssh-agent-crypt

Encrypt and decrypt using an SSH key in your agent. Bash, Node and Go share
one armor format.

```bash
echo "ok" | ssh-agent-crypt | ssh-agent-crypt -decrypt
```

## Install

```bash
npm install -g ssh-agent-crypt
go install github.com/131/ssh-agent-crypt/cmd/ssh-agent-crypt@latest

# Portable Bash script
curl -fsSL https://raw.githubusercontent.com/131/ssh-agent-crypt/master/bin/ssh-agent-crypt > ssh-agent-crypt
chmod +x ssh-agent-crypt

# Linux binary
wget -O ssh-agent-crypt https://github.com/131/ssh-agent-crypt/releases/latest/download/ssh-agent-crypt-linux-amd64
chmod +x ssh-agent-crypt

# Windows binary
curl.exe -fsSL -o ssh-agent-crypt.exe https://github.com/131/ssh-agent-crypt/releases/latest/download/ssh-agent-crypt-windows-amd64.exe
```

[Releases](https://github.com/131/ssh-agent-crypt/releases) include `SHA256SUMS`
and Authenticode-signed Windows binaries. Verify before installation.

## Usage

```bash
ssh-agent-crypt < secret.txt > secret.enc
ssh-agent-crypt -decrypt < secret.enc > secret.txt
```

Select a key by public/private file path, comment, SHA256 or MD5 fingerprint:

```bash
ssh-agent-crypt id_ed25519.pub < secret.txt > secret.enc
ssh-agent-crypt user@host < secret.txt > secret.enc
ssh-agent-crypt SHA256:abc123... < secret.txt > secret.enc
ssh-agent-crypt MD5:aa:bb:cc:dd:... < secret.txt > secret.enc
```

Without an argument, selection uses `SSH_AGENT_CRYPT_KEY`, then
`VAUTH_USER_IDENTITY` / `VAUTH_USER_MAIL`, then the first agent key.
Decryption prefers the armor's fingerprint when no explicit key is supplied.

```bash
export SSH_AGENT_CRYPT_KEY=user@host
ssh-agent-crypt < secret.txt > secret.enc
```

An explicit private key file also works without an agent:

```bash
ssh-agent-crypt ~/.ssh/id_ed25519 < secret.txt > secret.enc
```

Supported algorithms: Ed25519 and RSA. SSH uses `SSH_AUTH_SOCK`; native Windows
falls back to Pageant (0.75+) and OpenSSH pipes. Bash needs OpenSSH and OpenSSL.

## Format and security

Encryption uses AES-256-CBC and HMAC-SHA256, with key material derived from an
SSHSIG signature in the `ssh-agent-crypt` namespace. Encryption writes v3;
decryption also accepts v1/v2 armor.

```text
ssh-agent-crypt:v3:<fingerprint>.<salt_b64>.<iv_hex>.<ciphertext_b64>.<mac_hex>
```

The v3 MAC authenticates all fields, including the header. Whoever can use the
signing key can decrypt; protect the agent socket and any private key file.
OpenSSH `ssh-add -c` requires confirmation on each use.

## SDK and assessments

- [API and tests](API_and_tests.md)
- [Claude assessment](SECURITY_AUDIT_fable-5.1.md), [Sol assessment](SECURITY_AUDIT_gpt-6.1-sol.md).
  Each report states its assessed source and limitations.

## Credits

François Leurent/131, OpenAI Codex and Anthropic Claude.
Code signing courtesy of Essilor International.
