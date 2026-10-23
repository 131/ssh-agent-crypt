# Format fixtures

These are public, disposable test identities. **Never use these private keys
for real data or authentication.** The plaintext of every armor is the UTF-8
text `legacy token`, with no trailing newline; each armor ends with one LF.

- `v1.*.txt`: namespace `file`, no embedded fingerprint, MAC over
  `salt_b64.iv_hex.ciphertext_b64`.
- `v2.*.txt`: namespace `file`, embedded SHA256 fingerprint, MAC over
  `fingerprint.salt_b64.iv_hex.ciphertext_b64`.
- `v3.*.txt`: namespace `ssh-agent-crypt`, embedded SHA256 fingerprint, MAC
  over `ssh-agent-crypt:v3:fingerprint.salt_b64.iv_hex.ciphertext_b64`.

All versions sign the literal base64 salt text (not decoded salt bytes, and
without a newline), with empty SSHSIG reserved field and SHA-512 message hash.
RSA uses `rsa-sha2-512`; Ed25519 uses `ssh-ed25519`. The lowercase hex SHA-512
hash of the complete binary SSHSIG envelope is the seed text; SHA-256 of
`enc:` or `mac:` followed by that text yields the two subkeys. AES-256-CBC
uses PKCS#7 padding. Salt and IV are the values recorded in each armor.

The Go and npm suites read all six samples through private files, public files
and agent selectors (v1 requires an explicit selector here because another
identity is deliberately first). They reject relabeled v2/v3 headers and
mutations of every v3 field. Fixed salt/IV injection also requires each v3
writer to reproduce the **entire fixture byte for byte**, not merely round-trip
its own output. Go injects `Options.Rand`; the npm harness replaces only the
entropy calls in isolated Bash/Node subprocesses. Production entropy is intact.

The v1/v2 samples were also read successfully by the Bash implementation from
`dfcd8c7` during the October 23, 2026 follow-up. That checks legacy compatibility,
not the original generation provenance. These fixtures pin observable format
behavior; they do not constitute a security proof or independent published
vectors for every intermediate SSHSIG/seed/subkey byte. Do not regenerate them
just to make a changed implementation pass.
