//go:build !windows

package sshagentcrypt

import (
	"net"
	"os"
)

// DialAgent connects to the ssh-agent Unix socket at address.
func DialAgent(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}

// DefaultAgentAddress returns the agent address from SSH_AUTH_SOCK, or an
// empty string when no agent is configured.
func DefaultAgentAddress() string {
	return os.Getenv("SSH_AUTH_SOCK")
}
