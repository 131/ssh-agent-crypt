//go:build !windows

package sshagentcrypt

import "net"

func dialAgent(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}
