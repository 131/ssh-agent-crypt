//go:build windows

package sshagentcrypt

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// dialAgent connects to the OpenSSH-compatible named pipe exposed by the
// Windows OpenSSH agent or by Pageant (0.75+), e.g. \\.\pipe\openssh-ssh-agent.
func dialAgent(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}
