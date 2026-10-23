// Command ssh-agent-crypt seals stdin to stdout with an ssh-agent key, or
// unseals it with -decrypt. Same interface as the Bash and Node CLIs.
package main

import (
	"fmt"
	"io"
	"os"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  %[1]s [key]            < plaintext > encrypted
  %[1]s -decrypt [key]   < encrypted > plaintext

Key can be:
  - path to a key file
  - key comment (e.g. "user@host")
  - SHA256 fingerprint
  - MD5 fingerprint
  - omitted -> first key from ssh-agent

Notes:
  - Encryption: AES-256-CBC + HMAC-SHA256
  - Format:
      ssh-agent-crypt:v2:<fingerprint>.<salt_b64>.<iv_hex>.<ciphertext_b64>.<mac_hex>
`, os.Args[0])
	os.Exit(1)
}

func main() {
	decrypt := false
	selector := ""
	args := os.Args[1:]
	switch {
	case len(args) == 0:
	case args[0] == "-decrypt":
		decrypt = true
		if len(args) > 1 {
			selector = args[1]
		}
	case args[0][0] == '-':
		usage()
	default:
		selector = args[0]
	}

	// Read upstream completely before contacting the agent.
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	if decrypt {
		plaintext, err := sshagentcrypt.Decrypt(input, selector, nil)
		if err != nil {
			fail(err)
		}
		os.Stdout.Write(plaintext)
		return
	}
	armored, err := sshagentcrypt.Encrypt(input, selector, nil)
	if err != nil {
		fail(err)
	}
	os.Stdout.WriteString(armored)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
