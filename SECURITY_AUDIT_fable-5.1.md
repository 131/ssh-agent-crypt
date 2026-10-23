# Security audit — Codex (Anthropic Claude Fable 5.1)

One of two independent reviews of the design and of the three
implementations of [ssh-agent-crypt](README.md), scoring Coolness, Robustness
and Safety out of 20. The other review is in [SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).


Reviewed: `sshagentcrypt.go`, `agent_*.go`, `cmd/ssh-agent-crypt`,
`index.js`, `bin/ssh-agent-crypt`, the test suites, the fixtures and the
release workflows. `go vet ./...`, `go test ./...` and `npm test` pass
locally. The review assumes the `ssh-add -c` recommendation in the README is
followed where the agent supports it.

## Design, restated

The ciphertext carries a random 32-byte salt. Both sides ask the agent for the
SSHSIG signature of `SHA512(salt)` in the dedicated `ssh-agent-crypt`
namespace (hash `sha512`, exactly what `ssh-keygen -Y sign -n ssh-agent-crypt`
produces), hash the whole SSHSIG blob with SHA-512, and split it with
`SHA256("enc:"‖hex)` / `SHA256("mac:"‖hex)` into an AES-256-CBC key and an
HMAC-SHA256 key. Encrypt-then-MAC covers the header `ssh-agent-crypt:v3:` and
the textual `fingerprint.salt.iv.ciphertext`. Legacy v2 and v1 armors (generic
`file` namespace, header outside the MAC) are read but never written. The
scheme relies on one property that is not part of any signature scheme's
contract: **determinism**. Ed25519 (RFC 8032) and RSA PKCS#1 v1.5 happen to be
deterministic, which is why ECDSA and FIDO `sk-*` keys are refused by all
three implementations, from the agent and from key files alike.

## What holds

- Encrypt-then-MAC in the right order, MAC verified before any decryption, so
  CBC padding oracles are moot; Go and Node compare in constant time.
- A fresh salt means a fresh key per message, so IV reuse and CBC's IV
  requirements are irrelevant in practice.
- The format version is inside the MAC, so a v3 armor cannot be relabeled as
  v2 (or the reverse) without failing authentication.
- A dedicated SSHSIG namespace: a routine `ssh-keygen -Y sign -n file`
  signature never doubles as key material, and with `ssh-add -c` the prompt
  shows a request that is obviously not a file signature.
- Strict field parsing: fingerprint regex, exact field count, IV/ciphertext/MAC
  length checks, MAC covering the key fingerprint (no key-substitution
  confusion).
- With `ssh-add -c`, every derivation is a visible, user-confirmed event: a
  forwarded agent or a local process cannot harvest keys without a prompt
  per ciphertext, which is a far better position than a key file on disk.
- Three implementations cross-tested in every direction; `test/fixtures/`
  pins v1, v2 and v3 armors byte for byte, so a drift in any single writer or
  reader is caught.
- Go closes its agent connection and fails on unwritable output; the CLI
  rejects empty selectors and extra arguments instead of panicking.
- Signed Windows binaries, checksums, tests run before every publish.

## Weaknesses

Ordered by what I would fix first.

1. **Signing is decryption.** Anyone who can obtain one signature in the
   `ssh-agent-crypt` namespace over a chosen salt holds the message key.
   `ssh-add -c` turns that into a per-use prompt, but a prompt is only as good
   as the user's reading of it, and confirmation is agent-dependent: the
   Windows OpenSSH agent refuses `ssh-add -c` ("agent refused operation") and
   Pageant has no per-use confirmation, so on Windows the silent oracle
   remains.
2. **No key separation or rotation story.** The SSH identity is the only root
   of trust; rotating or revoking the SSH key silently orphans every
   ciphertext, there is no forward secrecy and no way to re-key without the
   plaintext.
3. **Decryptability depends on the signer's implementation, not only on the
   key.** The three implementations are interchangeable with a conforming
   agent (the cross tests prove it for Ed25519 and RSA), but the key material
   is whatever the agent actually signed. A hedged/randomised Ed25519 (some
   PKCS#11 modules, HSMs, future OpenSSH fault-attack countermeasures) breaks
   decryption outright. An agent that ignores the `rsa-sha2-512` flag and
   answers `ssh-rsa` (SHA-1) — a Pageant older than 0.75 over the legacy
   window protocol Node still uses — yields a blob Go and `ssh-keygen` would
   not reproduce, because Go hashes the format the agent returned while Node
   labels the signature `rsa-sha2-512` unconditionally. Such a ciphertext is
   readable only by Node with that same agent. Checking the returned format
   (Node) or refusing a non-`rsa-sha2-512` answer (both) would fail fast.
4. **Bash exposes the MAC key on the command line**: `openssl dgst -macopt
   hexkey:$mac_key` is visible in `/proc/*/cmdline` to every local user for
   the duration of the call (OpenSSL 3.x erases `enc -K` after parsing, not
   `-macopt`). Bash also compares MACs with `[ = ]`, not in constant time.
   Avoid the Bash implementation on shared machines.
5. **Ad-hoc KDF.** `SHA256(label ‖ hex(SHA512(blob)))` is sound but
   non-standard; HKDF-SHA256 with the salt as HKDF salt and the format version
   as `info` would be the textbook form. AES-CBC+HMAC rather than an AEAD is a
   concession to `openssl enc`; it is correct, just more surface than
   ChaCha20-Poly1305 or AES-GCM would be.
6. **Metadata.** The SHA256 fingerprint is in clear by design (key selection),
   so a ciphertext reveals *who* can decrypt it, and ciphertexts are
   linkable across contexts. No associated data binds a blob to its purpose,
   so two ciphertexts under the same key can be swapped (e.g. two cache files).
7. **Agent trust is unchecked.** A hostile agent (pipe squatting on
   `\\.\pipe\openssh-ssh-agent` when the service is down, a planted
   `SSH_AUTH_SOCK`) chooses the "signature" and therefore the encryption key of
   everything you seal. Inherent to the agent model, shared with `ssh` itself;
   `ssh-add -c` does not help here since the agent is the attacker.
8. **Legacy readers keep the legacy exposure.** v1/v2 ciphertexts are still
   derived from `-n file` signatures; as long as such data exists, a `file`
   signature over a salt-shaped message remains a key. Re-encrypt old data to
   retire that path.
9. **Framing differs between implementations.** Only the first line is
   parsed; trailing lines, a trailing newline or CRLF are tolerated
   differently by Bash, Node and Go. Nothing unsafe, but "the same armor" is
   not quite the same byte stream everywhere.
10. Minor: Go cannot read passphrase-protected key files while Bash can; no
    minimum RSA size; `Options.Rand` lets a library caller silently destroy
    the salt's entropy; `ssh2/lib/agent` is an internal module path, not a
    public API.

## Scores

| Criterion | Score | Reason |
| --- | --- | --- |
| Coolness | 16/20 | "ssh-agent is enough" is a genuinely good idea: no key file, no key export, no sidecar store, one armored line, three canonical implementations that agree byte for byte, Pageant pipe discovery done the PuTTY way. The dedicated namespace makes the trick (a deterministic signature as a secret) a declared one, but the user still has to understand it to use it safely. |
| Robustness | 16/20 | Encrypt-then-MAC, fresh key per message, authenticated header, strict field parsing, all key-type policies enforced in all three implementations, fixtures pinning every version in every reader. Loses for decryptability depending on what the agent actually signed (hedged Ed25519, an agent ignoring `rsa-sha2-512` goes unnoticed by Node), divergent framing and the home-made KDF. |
| Safety | 14/20 | The dedicated namespace and the authenticated header close the two cheapest attacks (benign-looking signing request, header downgrade); with `ssh-add -c` the signing oracle is a per-use prompt naming an odd namespace. Still: a signing capability is a decryption capability, no key separation or revocation story, no confirmation on the Windows agents, Bash exposing the MAC key in `ps`, agent trusted blindly. |
