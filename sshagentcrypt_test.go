package sshagentcrypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var repoRoot, _ = filepath.Abs(".")

type testAgent struct {
	t      *testing.T
	dir    string
	env    []string
	socket string
}

func startAgent(t *testing.T) *testAgent {
	t.Helper()
	for _, tool := range []string{"ssh-agent", "ssh-keygen", "ssh-add"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	out, err := exec.Command("ssh-agent", "-s").Output()
	if err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	socket := regexp.MustCompile(`SSH_AUTH_SOCK=([^;]+);`).FindStringSubmatch(string(out))
	pid := regexp.MustCompile(`SSH_AGENT_PID=([0-9]+);`).FindStringSubmatch(string(out))
	if socket == nil || pid == nil {
		t.Fatalf("unexpected ssh-agent output: %s", out)
	}
	a := &testAgent{t: t, dir: t.TempDir(), socket: socket[1]}
	a.env = append(os.Environ(), "SSH_AUTH_SOCK="+a.socket, "SSH_AGENT_PID="+pid[1])
	t.Cleanup(func() { a.run("ssh-agent", nil, "-k") })
	return a
}

func (a *testAgent) run(name string, stdin []byte, args ...string) []byte {
	a.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = a.env
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		a.t.Fatalf("%s %v: %v\n%s", name, args, err, stderr.String())
	}
	return out
}

// try runs a command and reports failure instead of aborting the test.
func (a *testAgent) try(name string, stdin []byte, args ...string) ([]byte, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = a.env
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return out, stderr.String(), err
}

func (a *testAgent) createKey(comment, keyType string) string {
	a.t.Helper()
	path := filepath.Join(a.dir, strings.NewReplacer("@", "_", "-", "_").Replace(comment))
	a.run("ssh-keygen", nil, "-q", "-t", keyType, "-N", "", "-C", comment, "-f", path)
	return path
}

func (a *testAgent) addKey(path string) {
	a.t.Helper()
	a.run("ssh-add", nil, "-q", path)
}

func (a *testAgent) options() *Options {
	return &Options{AgentSocket: a.socket}
}

func (a *testAgent) bash(stdin []byte, args ...string) []byte {
	a.t.Helper()
	return a.run("bash", stdin, append([]string{filepath.Join(repoRoot, "bin", "ssh-agent-crypt")}, args...)...)
}

func (a *testAgent) nodeAvailable() bool {
	if _, err := exec.LookPath("node"); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(repoRoot, "node_modules", "ssh2"))
	return err == nil
}

func (a *testAgent) node(script string, stdin []byte) []byte {
	a.t.Helper()
	return a.run("node", stdin, "-e", "const {encrypt, decrypt} = require(process.argv[1]); "+script, repoRoot)
}

func TestRoundTripFirstKey(t *testing.T) {
	a := startAgent(t)
	a.addKey(a.createKey("alpha@test", "ed25519"))
	plaintext := []byte("hello from go\nline2\n")
	armored, err := Encrypt(plaintext, "", a.options())
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^ssh-agent-crypt:v2:SHA256:[A-Za-z0-9+/]{43}\.[A-Za-z0-9+/=]+\.[0-9a-f]{32}\.[A-Za-z0-9+/=]+\.[0-9a-f]{64}\n$`).MatchString(armored) {
		t.Fatalf("unexpected armor: %q", armored)
	}
	decrypted, err := Decrypt([]byte(armored), "", a.options())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("got %q", decrypted)
	}
}

func TestCrossImplementationsAndSelectors(t *testing.T) {
	for _, keyType := range []string{"ed25519", "rsa"} {
		t.Run(keyType, func(t *testing.T) {
			a := startAgent(t)
			a.addKey(a.createKey("alpha@test", "ed25519"))
			selected := a.createKey("selected-"+keyType+"@test", keyType)
			a.addKey(selected)
			comment := "selected-" + keyType + "@test"
			sha256Fp := strings.Fields(string(a.run("ssh-keygen", nil, "-lf", selected+".pub")))[1]
			md5Fp := strings.Fields(string(a.run("ssh-keygen", nil, "-E", "md5", "-lf", selected+".pub")))[1]
			selectors := []string{comment, selected + ".pub", sha256Fp, md5Fp, strings.ReplaceAll(md5Fp, ":", "")[3:]}
			for _, selector := range selectors {
				plaintext := []byte("Unicode: coucou bibou 🐻\n" + selector)
				armored, err := Encrypt(plaintext, selector, a.options())
				if err != nil {
					t.Fatalf("%s: %v", selector, err)
				}
				if got := a.bash([]byte(armored), "-decrypt", comment); !bytes.Equal(got, plaintext) {
					t.Fatalf("bash decrypts go (%s): %q", selector, got)
				}
				if got, err := Decrypt(a.bash(plaintext, comment), selector, a.options()); err != nil || !bytes.Equal(got, plaintext) {
					t.Fatalf("go decrypts bash (%s): %q %v", selector, got, err)
				}
				if a.nodeAvailable() {
					script := "decrypt(require('fs').readFileSync(0)).then(s => process.stdout.write(s))"
					if got := a.node(script, []byte(armored)); !bytes.Equal(got, plaintext) {
						t.Fatalf("node decrypts go (%s): %q", selector, got)
					}
					script = "encrypt(require('fs').readFileSync(0), process.argv[2]).then(s => process.stdout.write(s))"
					nodeArmor := a.run("node", plaintext, "-e", "const {encrypt} = require(process.argv[1]); "+script, repoRoot, comment)
					if got, err := Decrypt(nodeArmor, selector, a.options()); err != nil || !bytes.Equal(got, plaintext) {
						t.Fatalf("go decrypts node (%s): %q %v", selector, got, err)
					}
				}
			}
			empty, err := Encrypt(nil, "", a.options())
			if err != nil {
				t.Fatal(err)
			}
			if got, err := Decrypt([]byte(empty), "", a.options()); err != nil || len(got) != 0 {
				t.Fatalf("empty: %q %v", got, err)
			}
			if got := a.bash([]byte(empty), "-decrypt"); len(got) != 0 {
				t.Fatalf("bash empty: %q", got)
			}
			wrong, _ := Encrypt([]byte("secret"), "alpha@test", a.options())
			if _, err := Decrypt([]byte(wrong), comment, a.options()); err == nil || err.Error() != "Authentication failed" {
				t.Fatalf("wrong key: %v", err)
			}
		})
	}
}

func TestPrivateKeyFileWithoutAgent(t *testing.T) {
	a := startAgent(t)
	options := &Options{AgentSocket: "/nonexistent/agent.sock"}
	for _, keyType := range []string{"ed25519", "rsa"} {
		key := a.createKey("private-"+keyType+"@test", keyType)
		a.env = append(a.env, "SSH_AUTH_SOCK=")
		armored, err := Encrypt([]byte("private key"), key, options)
		if err != nil {
			t.Fatal(err)
		}
		if got := a.bash([]byte(armored), "-decrypt", key); string(got) != "private key" {
			t.Fatalf("bash: %q", got)
		}
		if got, err := Decrypt(a.bash([]byte("reverse"), key), key, options); err != nil || string(got) != "reverse" {
			t.Fatalf("go: %q %v", got, err)
		}
	}
}

func TestLegacyV1(t *testing.T) {
	for _, keyType := range []string{"ed25519", "rsa"} {
		a := startAgent(t)
		key := a.createKey("legacy@test", keyType)
		a.addKey(key)
		armored, err := Encrypt([]byte("legacy token"), "", a.options())
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(armored, Prefix)), ".")
		salt, iv, ciphertext := parts[1], parts[2], parts[3]
		signed := a.run("ssh-keygen", []byte(salt), "-Y", "sign", "-f", key, "-n", "file")
		var signature string
		for _, line := range strings.Split(string(signed), "\n") {
			if line != "" && !strings.HasPrefix(line, "-----") {
				signature += line
			}
		}
		raw, _ := base64.StdEncoding.DecodeString(signature)
		sum := sha512.Sum512(raw)
		material := hex.EncodeToString(sum[:])
		macKey := sha256.Sum256([]byte("mac:" + material))
		payload := salt + "." + iv + "." + ciphertext
		mac := hmac.New(sha256.New, macKey[:])
		mac.Write([]byte(payload))
		legacy := []byte("ssh-agent-crypt:v1:" + payload + "." + hex.EncodeToString(mac.Sum(nil)) + "\n")
		for _, selector := range []string{"", "legacy@test"} {
			if got, err := Decrypt(legacy, selector, a.options()); err != nil || string(got) != "legacy token" {
				t.Fatalf("%s v1 (%q): %q %v", keyType, selector, got, err)
			}
		}
	}
}

func TestRejections(t *testing.T) {
	a := startAgent(t)
	a.addKey(a.createKey("alpha@test", "ed25519"))
	a.addKey(a.createKey("ec@test", "ecdsa"))
	armored, _ := Encrypt([]byte("secret"), "", a.options())
	tampered := []byte(strings.TrimSpace(armored))
	last := tampered[len(tampered)-1]
	if last == 'a' {
		tampered[len(tampered)-1] = 'b'
	} else {
		tampered[len(tampered)-1] = 'a'
	}
	cases := map[string]func() error{
		"tamper": func() error { _, err := Decrypt(tampered, "", a.options()); return err },
		"ecdsa":  func() error { _, err := Encrypt([]byte("x"), "ec@test", a.options()); return err },
		"missing key": func() error {
			_, err := Encrypt([]byte("x"), "missing@test", a.options())
			return err
		},
		"no agent": func() error {
			_, err := Encrypt([]byte("x"), "", &Options{AgentSocket: "/nonexistent/agent.sock"})
			return err
		},
		"header": func() error { _, err := Decrypt([]byte("nope"), "", a.options()); return err },
	}
	expected := map[string]string{
		"tamper": "Authentication failed", "ecdsa": "Unsupported key type: ecdsa-sha2-nistp256",
		"missing key": "Key not found: missing@test", "no agent": "Unable to list ssh-agent keys",
		"header": "Unsupported format header",
	}
	for name, run := range cases {
		err := run()
		if err == nil || !strings.HasPrefix(err.Error(), expected[name]) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCLIBinaryRoundTrip(t *testing.T) {
	a := startAgent(t)
	a.addKey(a.createKey("cli@test", "ed25519"))
	binary := filepath.Join(a.dir, "ssh-agent-crypt")
	a.run("go", nil, "build", "-o", binary, "./cmd/ssh-agent-crypt")
	input := []byte{0, 255, 128, 65, 10, 10}
	armored := a.run(binary, input)
	if got := a.bash(armored, "-decrypt"); !bytes.Equal(got, input) {
		t.Fatalf("bash decrypts cli: %v", got)
	}
	if got := a.run(binary, a.bash(input), "-decrypt"); !bytes.Equal(got, input) {
		t.Fatalf("cli decrypts bash: %v", got)
	}
	if out, stderr, err := a.try(binary, tamperLast(armored), "-decrypt"); err == nil || len(out) != 0 || !strings.Contains(stderr, "Authentication failed") {
		t.Fatalf("tampered: %q %q %v", out, stderr, err)
	}
	a.env = append(a.env, "SSH_AUTH_SOCK=/nonexistent/agent.sock")
	if out, stderr, err := a.try(binary, []byte("secret")); err == nil || len(out) != 0 || !strings.Contains(stderr, "Unable to list ssh-agent keys") {
		t.Fatalf("no agent: %q %q %v", out, stderr, err)
	}
}

func tamperLast(armored []byte) []byte {
	out := bytes.TrimSpace(append([]byte{}, armored...))
	if out[len(out)-1] == 'a' {
		out[len(out)-1] = 'b'
	} else {
		out[len(out)-1] = 'a'
	}
	return append(out, '\n')
}
