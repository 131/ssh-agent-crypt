//go:build windows

package sshagentcrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// OpenSSHAgentPipe is the named pipe of the Windows OpenSSH agent service.
const OpenSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// DialAgent connects to the OpenSSH-compatible named pipe exposed by the
// Windows OpenSSH agent or by Pageant (0.75+), e.g. \\.\pipe\openssh-ssh-agent.
func DialAgent(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}

// DefaultAgentAddress returns the agent address from SSH_AUTH_SOCK. Without
// it, the running Pageant (0.75+) named pipe is used when present, and the
// Windows OpenSSH agent pipe otherwise.
func DefaultAgentAddress() string {
	if address := os.Getenv("SSH_AUTH_SOCK"); address != "" {
		return address
	}
	if pipe := PageantPipeName(); pipe != "" && pipeExists(pipe) {
		return pipe
	}
	return OpenSSHAgentPipe
}

var (
	procCryptProtectMemory = windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptProtectMemory")
	procGetUserNameW       = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetUserNameW")
	procWaitNamedPipeW     = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")
)

const (
	cryptProtectMemoryBlockSize    = 16
	cryptProtectMemoryCrossProcess = 1
)

// PageantPipeName computes the named pipe of the current user's Pageant,
// \\.\pipe\pageant.<user>.<suffix>, the way PuTTY does: the suffix is the
// SHA-256 of "Pageant" obfuscated with CryptProtectMemory (cross-process key,
// stable within the logon session), as in PuTTY 0.75+. Empty when the user
// name is unavailable.
func PageantPipeName() string {
	user := windowsUserName()
	if user == "" {
		return ""
	}
	return `\\.\pipe\pageant.` + user + "." + obfuscate("Pageant")
}

func obfuscate(name string) string {
	size := (len(name) + 1 + cryptProtectMemoryBlockSize - 1) / cryptProtectMemoryBlockSize * cryptProtectMemoryBlockSize
	data := make([]byte, size)
	copy(data, name)
	if procCryptProtectMemory.Find() == nil {
		// Failure leaves data in clear, like PuTTY.
		procCryptProtectMemory.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(size), cryptProtectMemoryCrossProcess)
	}
	// PuTTY hashes the SSH string encoding (length-prefixed) of the result.
	digest := sha256.Sum256(sshString(data))
	return hex.EncodeToString(digest[:])
}

func windowsUserName() string {
	var size uint32
	windows.GetUserNameEx(windows.NameUserPrincipal, nil, &size)
	if size > 0 {
		buffer := make([]uint16, size)
		if err := windows.GetUserNameEx(windows.NameUserPrincipal, &buffer[0], &size); err == nil {
			user := windows.UTF16ToString(buffer)
			if at := strings.IndexByte(user, '@'); at >= 0 {
				user = user[:at]
			}
			return user
		}
	}
	size = 256
	buffer := make([]uint16, size)
	ok, _, _ := procGetUserNameW.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return ""
	}
	return windows.UTF16ToString(buffer)
}

func pipeExists(name string) bool {
	pipe, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	// Fails with ERROR_FILE_NOT_FOUND when no server listens on this name;
	// a busy server times out, which still proves the pipe exists.
	ok, _, err := procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(pipe)), 1)
	return ok != 0 || err == windows.ERROR_SEM_TIMEOUT
}
