// Package sshagentcrypt seals and unseals data with a key held by the
// ssh-agent, without private key access. It is the Go implementation of the
// ssh-agent-crypt v2 format shared with the Bash and Node implementations.
package sshagentcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Prefix is the armor header of the current format.
const Prefix = "ssh-agent-crypt:v2:"

const legacyPrefix = "ssh-agent-crypt:v1:"

var fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// Options tune agent access. The zero value reads SSH_AUTH_SOCK from the
// process environment and uses crypto/rand.
type Options struct {
	// AgentSocket is the ssh-agent address: a Unix socket path, or a named
	// pipe on Windows. Empty means SSH_AUTH_SOCK.
	AgentSocket string
	// Rand is the entropy source for salt and IV; nil means crypto/rand.
	Rand io.Reader
}

func (o *Options) agentSocket() string {
	if o != nil && o.AgentSocket != "" {
		return o.AgentSocket
	}
	return os.Getenv("SSH_AUTH_SOCK")
}

func (o *Options) rand() io.Reader {
	if o != nil && o.Rand != nil {
		return o.Rand
	}
	return rand.Reader
}

type derivedKeys struct {
	fingerprint string
	enc         []byte
	mac         []byte
}

// signer abstracts an agent-held key or a local private key.
type signer interface {
	PublicKey() ssh.PublicKey
	Sign(data []byte) (*ssh.Signature, error)
}

type agentSigner struct {
	client agent.ExtendedAgent
	key    ssh.PublicKey
}

func (s *agentSigner) PublicKey() ssh.PublicKey { return s.key }

func (s *agentSigner) Sign(data []byte) (*ssh.Signature, error) {
	var flags agent.SignatureFlags
	if s.key.Type() == ssh.KeyAlgoRSA {
		flags = agent.SignatureFlagRsaSha512
	}
	return s.client.SignWithFlags(s.key, data, flags)
}

type localSigner struct {
	signer ssh.Signer
}

func (s *localSigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }

func (s *localSigner) Sign(data []byte) (*ssh.Signature, error) {
	if s.signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		algorithmSigner, ok := s.signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("RSA key does not support rsa-sha2-512")
		}
		return algorithmSigner.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	}
	return s.signer.Sign(rand.Reader, data)
}

// Fingerprint returns the SHA256 fingerprint of key, as printed by ssh-keygen -l.
func Fingerprint(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

func checkAlgorithm(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoED25519:
		return nil
	}
	return fmt.Errorf("Unsupported key type: %s", key.Type())
}

func resolveKey(selector string, options *Options) (signer, error) {
	if selector != "" {
		if body, err := os.ReadFile(selector); err == nil {
			return resolveKeyFile(body, options)
		}
	}
	client, closeAgent, err := connectAgent(options)
	if err != nil {
		return nil, err
	}
	keys, err := client.List()
	if err != nil {
		closeAgent()
		return nil, fmt.Errorf("Unable to list ssh-agent keys: %w", err)
	}
	if len(keys) == 0 {
		closeAgent()
		return nil, errors.New("No keys in ssh-agent")
	}
	if selector == "" {
		return &agentSigner{client, keys[0]}, nil
	}
	md5Selector := strings.ReplaceAll(strings.TrimPrefix(selector, "MD5:"), ":", "")
	for _, key := range keys {
		md5 := strings.ReplaceAll(ssh.FingerprintLegacyMD5(key), ":", "")
		if key.Comment == selector || Fingerprint(key) == selector || md5 == md5Selector {
			return &agentSigner{client, key}, nil
		}
	}
	closeAgent()
	return nil, fmt.Errorf("Key not found: %s", selector)
}

func resolveKeyFile(body []byte, options *Options) (signer, error) {
	if private, err := ssh.ParsePrivateKey(body); err == nil {
		return &localSigner{private}, nil
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		return nil, fmt.Errorf("Unsupported key file: %w", err)
	}
	// Public key file: the agent must hold the matching private key.
	client, closeAgent, err := connectAgent(options)
	if err != nil {
		return nil, err
	}
	keys, err := client.List()
	if err != nil {
		closeAgent()
		return nil, fmt.Errorf("Unable to list ssh-agent keys: %w", err)
	}
	for _, key := range keys {
		if bytes.Equal(key.Marshal(), public.Marshal()) {
			return &agentSigner{client, key}, nil
		}
	}
	closeAgent()
	return nil, fmt.Errorf("Key not found: %s", Fingerprint(public))
}

func connectAgent(options *Options) (agent.ExtendedAgent, func(), error) {
	address := options.agentSocket()
	if address == "" {
		return nil, nil, errors.New("No ssh-agent (SSH_AUTH_SOCK is not set)")
	}
	conn, err := dialAgent(address)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to list ssh-agent keys: %w", err)
	}
	return agent.NewClient(conn), func() { conn.Close() }, nil
}

func sshString(value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(out, uint32(len(value)))
	copy(out[4:], value)
	return out
}

// deriveKeys reproduces the OpenSSH SSHSIG envelope over the salt, as
// `ssh-keygen -Y sign -n file` would produce, and hashes it into key material.
func deriveKeys(salt string, selector string, options *Options) (*derivedKeys, error) {
	key, err := resolveKey(selector, options)
	if err != nil {
		return nil, err
	}
	public := key.PublicKey()
	if err := checkAlgorithm(public); err != nil {
		return nil, err
	}

	message := sha512.Sum512([]byte(salt))
	fields := bytes.Join([][]byte{sshString([]byte("file")), sshString(nil), sshString([]byte("sha512"))}, nil)
	data := bytes.Join([][]byte{[]byte("SSHSIG"), fields, sshString(message[:])}, nil)

	signature, err := key.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("Unable to derive key material: %w", err)
	}
	blob := bytes.Join([][]byte{
		[]byte("SSHSIG"), {0, 0, 0, 1}, sshString(public.Marshal()), fields,
		sshString(ssh.Marshal(signature)),
	}, nil)
	material := hex.EncodeToString(func() []byte { sum := sha512.Sum512(blob); return sum[:] }())
	enc := sha256.Sum256([]byte("enc:" + material))
	mac := sha256.Sum256([]byte("mac:" + material))
	return &derivedKeys{fingerprint: Fingerprint(public), enc: enc[:], mac: mac[:]}, nil
}

func pkcs7Pad(input []byte, size int) []byte {
	padding := size - len(input)%size
	return append(append([]byte{}, input...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(input []byte, size int) ([]byte, error) {
	if len(input) == 0 || len(input)%size != 0 {
		return nil, errors.New("Invalid padding")
	}
	padding := int(input[len(input)-1])
	if padding == 0 || padding > size {
		return nil, errors.New("Invalid padding")
	}
	for _, b := range input[len(input)-padding:] {
		if int(b) != padding {
			return nil, errors.New("Invalid padding")
		}
	}
	return input[:len(input)-padding], nil
}

// Encrypt seals input with the key designated by selector (file path, comment,
// SHA256 or MD5 fingerprint; empty selects the first agent key). It returns a
// single armored line terminated by a newline.
func Encrypt(input []byte, selector string, options *Options) (string, error) {
	salt := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(options.rand(), salt); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(options.rand(), iv); err != nil {
		return "", err
	}
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	keys, err := deriveKeys(saltB64, selector, options)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(keys.enc)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(input, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	payload := keys.fingerprint + "." + saltB64 + "." + hex.EncodeToString(iv) + "." + base64.StdEncoding.EncodeToString(ciphertext)
	mac := hmac.New(sha256.New, keys.mac)
	mac.Write([]byte(payload))
	return Prefix + payload + "." + hex.EncodeToString(mac.Sum(nil)) + "\n", nil
}

// Decrypt unseals the first line of input. For v2 armor the embedded
// fingerprint selects the key unless selector is given; v1 armor falls back to
// the selector or the first agent key.
func Decrypt(input []byte, selector string, options *Options) ([]byte, error) {
	line, _, _ := strings.Cut(string(input), "\n")
	line = strings.TrimSuffix(line, "\r")
	var payload string
	var parts []string
	switch {
	case strings.HasPrefix(line, Prefix):
		payload = strings.TrimPrefix(line, Prefix)
		parts = strings.Split(payload, ".")
		fingerprint := parts[0]
		parts = parts[1:]
		if !fingerprintPattern.MatchString(fingerprint) {
			return nil, errors.New("Invalid key fingerprint")
		}
		if selector == "" {
			selector = fingerprint
		}
	case strings.HasPrefix(line, legacyPrefix):
		payload = strings.TrimPrefix(line, legacyPrefix)
		parts = strings.Split(payload, ".")
	default:
		return nil, errors.New("Unsupported format header")
	}
	if len(parts) != 4 {
		return nil, errors.New("Invalid payload")
	}
	salt, ivHex, ciphertextB64, macHex := parts[0], parts[1], parts[2], parts[3]
	keys, err := deriveKeys(salt, selector, options)
	if err != nil {
		return nil, err
	}
	authenticated := payload[:strings.LastIndex(payload, ".")]
	mac := hmac.New(sha256.New, keys.mac)
	mac.Write([]byte(authenticated))
	expected := mac.Sum(nil)
	actual, err := hex.DecodeString(macHex)
	if err != nil || len(actual) != len(expected) || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return nil, errors.New("Authentication failed")
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("Invalid IV")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext")
	}
	block, err := aes.NewCipher(keys.enc)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext, block.BlockSize())
}
