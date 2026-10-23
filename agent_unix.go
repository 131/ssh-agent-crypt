//go:build !windows

package sshagentcrypt

import "net"

// DialAgent connects to the ssh-agent Unix socket at address.
func DialAgent(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}
