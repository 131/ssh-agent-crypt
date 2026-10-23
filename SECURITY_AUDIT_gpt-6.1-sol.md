# Security audit — Codex (OpenAI GPT 6.1-sol)

One of two independent reviews of the design and of the three
implementations of [ssh-agent-crypt](README.md), scoring Coolness, Robustness
and Safety out of 20. The other review is in [SECURITY_AUDIT_fable-5.1.md](SECURITY_AUDIT_fable-5.1.md).


## Scope and method

Source review of package/module version 1.4.0, covering the Bash, Node and Go
implementations, tests, fixtures and release configuration. The code writes v3
and reads v1/v2/v3. This is not a formal security proof or a Windows runtime
audit.

On Linux/amd64, with Go 1.24.0, Node 22.22.2, Bash 5.2.37, OpenSSH 10.0p2 and
OpenSSL 3.5.5, `go vet ./...`, `go test ./...` and `npm test` (28 tests, none
skipped) pass. A Windows/amd64 cross-build also passes. Validation uses temporary
identities and isolated agents; it does not cover hosted release jobs or Windows
agent execution.

## Design, restated

Each encryption generates a 32-byte random salt and a 16-byte random IV. It
signs the **base64 text of the salt**, without a newline, using an OpenSSH
SSHSIG message with namespace `ssh-agent-crypt`, empty reserved field and
SHA-512 message hash. Bash uses `ssh-keygen -Y sign`; Node and Go reconstruct
the same wire representation. RSA requests `rsa-sha2-512`; Ed25519 uses its
native signature. Signing must be deterministic and serialization identical:
decryption must reproduce exactly the same signature, not merely another
valid signature over the same message.

The seed is the lowercase hexadecimal SHA-512 digest of the **complete binary
SSHSIG envelope**, including public key and signature. SHA-256 of `enc:` plus
that hex text gives the AES key; SHA-256 of `mac:` plus that text gives a
separate HMAC key. AES-256-CBC with PKCS#7 padding is followed by HMAC-SHA256
over the literal text
`ssh-agent-crypt:v3:fingerprint.salt.iv.ciphertext`. The v3 header is
authenticated; the final newline and MAC field itself are not. An explicit
selector overrides embedded fingerprint selection, but the embedded field is
still authenticated.

Legacy readers deliberately use namespace `file` and omit the header from the
MAC. v2 has the same five-field layout as v3; v1 omits the fingerprint and
requires the original first-key/explicit-selector behavior. No legacy writer
is used in production. Changing a v3 label to v2, or vice versa, fails
authentication; v1 cannot be obtained by simply relabeling either layout.

This is symmetric encryption backed by a signing capability, not public-key
encryption. The salt, IV and fingerprint are public; the exact signature used
for derivation must remain secret. Anyone obtaining it, or able to request it,
can decrypt and create valid MACs. There is no forward secrecy or retroactive
revocation after key compromise. Losing the signing key loses access to the
data. The fingerprint discloses the SSH identity, and CBC exposes padded length.

## What holds

- Encrypt-then-MAC with labeled independent subkeys, a random IV and fresh
  salt is sensible. All three readers verify the MAC before CBC decryption;
  Go/Node compare equal-length MAC bytes in constant time. Bash's string
  comparison does not offer that timing guarantee. The review identifies no
  practical break in the supported canonical path or reason for an emergency
  CBC replacement.
- **Bash enforces RSA/Ed25519 for file selectors.** `;;` keeps public lines
  out of `KEY_FILE`; public files sign via the agent, not a nearby private file.
  Private files are inspected with `ssh-keygen -l`, and both
  branches enforce RSA/Ed25519 before signing. Tests reject ECDSA public/private
  files with and without an agent, and retain encrypted RSA/Ed25519 private
  files usable via an already-unlocked agent. Inspection, fingerprinting and
  signing use regular descriptors for the private file itself: OpenSSH must not
  substitute a stale `.pub` sibling that changes the type/identity. A regression
  test covers both ECDSA rejection and actual RSA selection with mismatched
  siblings. The policy also runs on decryption.
- **v3 isolates the signing domain and authenticates the header.** A routine
  `ssh-keygen -Y sign -n file` signature does not provide v3 key material.
  Namespace and authenticated prefix agree across all three implementations;
  v1/v2 remain explicitly separate. Legacy data uses the generic namespace and
  unauthenticated header until re-encrypted. All supported versions use the same
  labeled-hash KDF.
- **Go manages connection lifetime and CLI errors explicitly.** Successful
  signers retain the connection closer; `defer key.Close()` covers derivation
  success, algorithm rejection and signing failure. Resolution failures close
  explicitly. Repeated success/rejection/authentication-failure calls are tested
  with GC disabled so finalizers cannot hide leaks. CLI output errors are fatal
  in encrypt and decrypt, tested with `/dev/full`; an empty selector selects
  the first agent key and extra arguments are rejected. Go usage/package text
  describes v3. Public ECDSA files are rejected before connecting to an agent,
  matching the other implementations even when no agent is available.
- **Fixtures pin both readers and v3 writers.** RSA/Ed25519 v1/v2/v3 samples
  are read through private/public files and agent selectors. Fixed entropy
  makes each Bash/Node/Go v3 writer reproduce the entire stored armor byte for
  byte. Tests mutate every v3 field using an explicit correct selector (so a
  fingerprint mutation cannot be dismissed merely as a key lookup failure),
  reject v2/v3 relabeling, and retain legacy/key-reordering coverage. The fixtures
  are static disposable test identities, not real credentials; provenance and
  limitations are documented in `test/fixtures/README.md`.
- **Node validates the MAC field before agent access.** It requires exactly
  64 hex characters and rejects suffixes such as `zz` after a valid MAC. CRLF
  is normalized explicitly, agreeing with Go. Valid v3 serialization uses a
  lowercase hexadecimal MAC and a terminating LF.
- Unix Go/Node agent work avoids subprocesses. Bash and the Go CLI preserve
  binary bytes and trailing newlines; Bash also tests refused signing and
  producer/consumer pipelines. Node's Pageant support uses a bundled `ssh2`
  helper executable, so subprocess-free claims need that Windows caveat.

## Remaining points to improve, in priority order

1. **Keep the signature-as-secret authorization boundary explicit.** The
   dedicated namespace prevents cross-purpose `file` signature reuse, not
   unrestricted or forwarded agent access: that caller can request the new
   namespace too. Treat signature logs as sensitive, define backups/recovery
   and do not treat `ssh-add -c` as operation-specific authorization. It prompts
   for signatures; it does not cryptographically distinguish encryption from
   decryption or guarantee informed consent. The legacy readers retain
   the generic namespace. A dedicated SSH key and re-encryption are meaningful
   operational options. Signature unforgeability alone is not a proof of this
   derivation; HKDF is a possible future specified KDF, not an urgent fix for a
   demonstrated break of the current labeled hashes.

2. **Node returns raw bytes.** Encrypt accepts a string or a `Buffer`,
   decrypt resolves to a `Buffer`; decoding is the caller's decision. A
   cross-implementation test round-trips non-UTF-8 bytes through Node, Bash
   and Go. Callers upgrading from the UTF-8-string API must add `.toString()`.

3. **Specify one armor grammar and framing policy.** Full canonical
   salt/IV/base64/ciphertext validation before signing is missing. Go checks field counts and decoded IV/ciphertext
   sizes, but does so partly after agent access; Bash parsing is less strict.
   Hex case acceptance also differs. Bash requires a terminating LF and rejects
   CRLF, whereas Go/Node accept unterminated lines and CRLF. All three read only
   the first record and ignore a trailing second record. Decide whether this is
   an intentional first-record API or whether tails must be rejected. Bound input
   size and document that these are whole-input, memory-buffered tools, not
   streaming encryption.

4. **Test nonstandard agents and bound their lifetime.** Go closes its
   connections, but neither request deadlines nor cancellation bound a stalled
   peer. Determinism depends on the agent: hedged/randomized Ed25519, or
   ignored RSA signature flags, can break recovery/interoperability. Go includes
   the returned signature algorithm in the envelope; Node labels it with the
   requested algorithm without checking what the agent actually returned. The
   OpenSSH tests establish the normal path, not every agent's behavior. Encrypted
   private files are another intentional interface difference: Go/Node do not
   provide passphrase callbacks, while Bash delegates to OpenSSH. Review coverage
   does not include an agent/mock conformance suite or native Windows runtime
   evidence.

5. **Retain the portability and release-evidence cautions.** Global npm
   installation gives the Node CLI; the Bash script stays in the package as
   a portable alternative, untested on Bash 3.2. The
   minimum supported Bash version needs a tested declaration; review coverage
   does not include macOS Bash 3.2. CI tests Ubuntu/Node 20 and cross-builds
   Windows; macOS, ARM, Pageant/OpenSSH on Windows, discovery/fallback and RSA
   flags are not runtime validated. A cross-build is not a transport test.

   Both npm/test workflows use `npm install`; `.npmrc` disables lockfile use
   and `package-lock.json` is not tracked. Consider an enforced lockfile with
   `npm ci`, a common test gate for npm/binary publication, immutable action/
   signing-helper pins, tag/package version agreement and installed-artifact
   tests. Binary-release Go tests can skip the optional Node checks because that
   job installs no Node dependencies. npm tests run under Node 20 but publication
   switches to Node 24 without re-testing. Signing hooks/checksums exist, but
   published Authenticode, checksums and signing-server behavior are outside
   this audit's scope.

   Exact v3 writer fixtures are stronger than round-trips, but not a formal
   independent specification of every signed/envelope/seed/subkey byte. Do not
   regenerate fixtures to accommodate a regression. Parser fuzzing,
   authenticated invalid-padding/IV/ciphertext cases, and mock-agent failure/
   algorithm tests are useful additions.

## Scores

| Criterion | Score / 20 | Justification |
| --- | ---: | --- |
| Coolness | 18 | Compact and useful reuse of an agent across three interoperable implementations, with explicit domain/version isolation. Encryption-specific authorization and recovery responsibilities still need care. |
| Robustness | 16 | Binary-preserving Bash/Go I/O, explicit Go output-error handling and connection cleanup, and Node MAC validation support the normal path. Exact writer fixtures, field mutation and resource tests strengthen confidence; parser/framing differences, nonstandard agents and native Windows gaps remain. |
| Safety | 15 | Encrypt-then-MAC, fresh salt/IV, labeled subkeys and v3 domain/header authentication are meaningful protections. Signing access still grants decryption, legacy data uses the generic signing namespace and unauthenticated headers, signatures are sensitive and Bash command-line MAC-key exposure remains. Not a security certification. |

**Release recommendation:** no release blocker is identified on the supported
OpenSSH RSA/Ed25519 path. Keep v3 as the write format with legacy-only readers,
ship the fixtures with the tests, clarify framing/threat-model/support claims
and do not market the scores or Windows cross-build as a security/runtime
certification.

