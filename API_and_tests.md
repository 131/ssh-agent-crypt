# ssh-agent-crypt: API, SDK and tests

Back to the [README](README.md).

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

## Agent transport

Node and Go only need a reachable agent at `SSH_AUTH_SOCK` (Unix socket, or a
Windows named pipe such as `\\.\pipe\openssh-ssh-agent`). On Windows without
`SSH_AUTH_SOCK`, the Go implementation connects to the running Pageant (0.75
or later, whose named pipe is derived the way PuTTY does it), and falls back
to the Windows OpenSSH agent pipe; the Node implementation uses the legacy
Pageant window protocol.

The Bash CLI needs `bash`, `openssl` and `ssh-agent`, `ssh-add`, `ssh-keygen`.

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
