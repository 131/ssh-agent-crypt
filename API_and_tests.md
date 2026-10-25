# API and tests

## Node

```js
const {encrypt, decrypt} = require('ssh-agent-crypt');
const armored = await encrypt('secret');
const plaintext = (await decrypt(armored)).toString();
```

`encrypt(input, key, {env})` accepts a string/Buffer and resolves to an armored
line. `decrypt(input, key, {env})` resolves to a Buffer. Key and environment
overrides are optional; failures reject.

## Go

```go
import sshagentcrypt "github.com/131/ssh-agent-crypt"

armored, err := sshagentcrypt.Encrypt([]byte("secret"), "", nil)
plaintext, err := sshagentcrypt.Decrypt([]byte(armored), "", nil)
```

`Encrypt` returns `(string, error)`; `Decrypt` returns `([]byte, error)`.
The key selector follows [CLI selection](README.md#usage). Optional `*Options`
provides `AgentSocket`, `DefaultKey` and `Rand` overrides.

`DefaultAgentAddress`, `DialAgent` and Windows `PageantPipeName` support shared
agent transport. Native Windows discovers Pageant/OpenSSH pipes without
`SSH_AUTH_SOCK`; Node uses ssh2's Pageant transport.

## Tests

```bash
npm test
go test ./...
```

Tests use throwaway keys/agents and verify Bash/Node/Go cross-reading, key
selection and legacy/current armor fixtures. Node checks Go when available;
Go checks Node when npm dependencies are installed.
