// Command ssh-agent-crypt seals stdin to stdout with an ssh-agent key, or
// unseals it with -decrypt. Same interface as the Bash and Node CLIs.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

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
  - omitted -> SSH_AGENT_CRYPT_KEY, VAUTH_USER_IDENTITY, VAUTH_USER_MAIL,
               else first key from ssh-agent

Notes:
  - Encryption: AES-256-CBC + HMAC-SHA256
  - Format:
      ssh-agent-crypt:v3:<fingerprint>.<salt_b64>.<iv_hex>.<ciphertext_b64>.<mac_hex>
    (v2 and v1 payloads remain readable)
`, "ssh-agent-crypt")
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
		if len(args) > 2 {
			usage()
		}
		if len(args) > 1 {
			if strings.HasPrefix(args[1], "-") {
				usage()
			}
			selector = args[1]
		}
	case strings.HasPrefix(args[0], "-"), len(args) > 1:
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
		write(plaintext)
		return
	}
	armored, err := sshagentcrypt.Encrypt(input, selector, nil)
	if err != nil {
		fail(err)
	}
	write([]byte(armored))
}

func write(output []byte) {
	if _, err := os.Stdout.Write(output); err != nil {
		fail(fmt.Errorf("Unable to write output: %w", err))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
