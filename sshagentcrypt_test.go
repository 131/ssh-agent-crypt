package sshagentcrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
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
	// Tests pick keys explicitly or expect the first agent key: scrub the
	// default-key variables a developer shell may carry, in-process and for
	// the subprocesses.
	for _, name := range defaultKeyEnv {
		t.Setenv(name, "")
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

func (a *testAgent) node(script string, stdin []byte, args ...string) []byte {
	a.t.Helper()
	return a.run("node", stdin, append([]string{"-e", "const {encrypt, decrypt} = require(process.argv[1]); " + script, repoRoot}, args...)...)
}

func TestRoundTripFirstKey(t *testing.T) {
	a := startAgent(t)
	a.addKey(a.createKey("alpha@test", "ed25519"))
	plaintext := []byte("hello from go\nline2\n")
	armored, err := Encrypt(plaintext, "", a.options())
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^ssh-agent-crypt:v3:SHA256:[A-Za-z0-9+/]{43}\.[A-Za-z0-9+/=]+\.[0-9a-f]{32}\.[A-Za-z0-9+/=]+\.[0-9a-f]{64}\n$`).MatchString(armored) {
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

// TestFixtures pins the armor formats: v1 and v2 samples were produced by the
// pre-v3 implementations, v3 by the current one, all with the fixture keys.
// Every implementation must read every version, through the agent and through
// the key file, and a relabeled header must fail authentication.
func TestFixtures(t *testing.T) {
	for _, keyType := range []string{"ed25519", "rsa"} {
		t.Run(keyType, func(t *testing.T) {
			a := startAgent(t)
			a.addKey(a.createKey("alpha@test", "ed25519"))
			key := filepath.Join(repoRoot, "test", "fixtures", keyType)
			a.addKey(key)
			for _, version := range []string{"v1", "v2", "v3"} {
				armored, err := os.ReadFile(filepath.Join(repoRoot, "test", "fixtures", version+"."+keyType+".txt"))
				if err != nil {
					t.Fatal(err)
				}
				selectors := []string{key, key + ".pub", "fixture-" + keyType + "@test"}
				if version != "v1" {
					selectors = append(selectors, "")
				}
				for _, selector := range selectors {
					if got, err := Decrypt(armored, selector, a.options()); err != nil || string(got) != "legacy token" {
						t.Fatalf("%s go (%q): %q %v", version, selector, got, err)
					}
					if got := a.bash(armored, "-decrypt", selector); string(got) != "legacy token" {
						t.Fatalf("%s bash (%q): %q", version, selector, got)
					}
					if a.nodeAvailable() {
						if got := a.node("decrypt(require('fs').readFileSync(0), process.argv[2] || undefined).then(out => process.stdout.write(out))", armored, selector); string(got) != "legacy token" {
							t.Fatalf("%s node (%q): %q", version, selector, got)
						}
					}
				}
				if version == "v3" {
					fields := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(armored)), Prefix), ".")
					for i := range fields {
						changed := append([]string(nil), fields...)
						if i == 0 {
							changed[i] = "SHA256:" + strings.Repeat("A", 43)
						} else if changed[i][0] == 'a' {
							changed[i] = "b" + changed[i][1:]
						} else {
							changed[i] = "a" + changed[i][1:]
						}
						if got, err := Decrypt([]byte(Prefix+strings.Join(changed, ".")), key, a.options()); err == nil || err.Error() != "Authentication failed" || len(got) != 0 {
							t.Fatalf("v3 field %d mutation: %q %v", i, got, err)
						}
					}
					parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(armored)), Prefix), ".")
					salt, err := base64.StdEncoding.DecodeString(parts[1])
					if err != nil {
						t.Fatal(err)
					}
					iv, err := hex.DecodeString(parts[2])
					if err != nil {
						t.Fatal(err)
					}
					for _, selector := range []string{key, key + ".pub", "fixture-" + keyType + "@test"} {
						options := &Options{AgentSocket: a.socket, Rand: bytes.NewReader(append(salt, iv...))}
						got, err := Encrypt([]byte("legacy token"), selector, options)
						if err != nil || got != string(armored) {
							t.Fatalf("fixed Go writer (%q): %q %v", selector, got, err)
						}
					}
				}
				if version == "v1" {
					continue
				}
				other := map[string]string{"v2": "v3", "v3": "v2"}[version]
				relabeled := []byte(strings.Replace(string(armored), "ssh-agent-crypt:"+version+":", "ssh-agent-crypt:"+other+":", 1))
				if _, err := Decrypt(relabeled, "", a.options()); err == nil || err.Error() != "Authentication failed" {
					t.Fatalf("%s relabeled as %s: %v", version, other, err)
				}
			}
		})
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
	// An empty selector means the default key, like no selector at all.
	if got := a.bash(a.run(binary, input, ""), "-decrypt"); !bytes.Equal(got, input) {
		t.Fatalf("empty selector: %v", got)
	}
	for _, args := range [][]string{{"a", "b"}, {"-decrypt", "a", "b"}, {"-x"}} {
		if out, stderr, err := a.try(binary, input, args...); err == nil || len(out) != 0 || !strings.Contains(stderr, "Usage:") {
			t.Fatalf("args %v: %q %q %v", args, out, stderr, err)
		}
	}
	if devFull, err := os.OpenFile("/dev/full", os.O_WRONLY, 0); err == nil {
		defer devFull.Close()
		for _, decrypt := range []bool{false, true} {
			cmd := exec.Command(binary)
			cmd.Stdin = bytes.NewReader(input)
			if decrypt {
				cmd = exec.Command(binary, "-decrypt")
				cmd.Stdin = bytes.NewReader(armored)
			}
			cmd.Env = a.env
			cmd.Stdout = devFull
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil || !strings.Contains(stderr.String(), "Unable to write output") {
				t.Fatalf("output error (decrypt=%t): %q %v", decrypt, stderr.String(), err)
			}
		}
	}
	a.env = append(a.env, "SSH_AUTH_SOCK=/nonexistent/agent.sock")
	if out, stderr, err := a.try(binary, []byte("secret")); err == nil || len(out) != 0 || !strings.Contains(stderr, "Unable to list ssh-agent keys") {
		t.Fatalf("no agent: %q %q %v", out, stderr, err)
	}
}

// TestAgentConnectionsClosed checks that Encrypt and Decrypt do not keep the
// agent connection open once the key material is derived.
func TestAgentConnectionsClosed(t *testing.T) {
	a := startAgent(t)
	a.addKey(a.createKey("fd@test", "ed25519"))
	a.addKey(a.createKey("ec-fd@test", "ecdsa"))
	options := &Options{AgentSocket: a.socket}
	// Disable finalizers so GC cannot conceal a leaked connection.
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	before := openFiles(t)
	for i := 0; i < 20; i++ {
		armored, err := Encrypt([]byte("fd"), "", options)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decrypt([]byte(armored), "", options); err != nil {
			t.Fatal(err)
		}
		for _, selector := range []string{"ec-fd@test", "missing@test"} {
			if _, err := Encrypt([]byte("fd"), selector, options); err == nil {
				t.Fatalf("expected rejection for %s", selector)
			}
		}
		if _, err := Decrypt(tamperLast([]byte(armored)), "", options); err == nil {
			t.Fatal("expected authentication failure")
		}
	}
	if after := openFiles(t); after > before {
		t.Fatalf("open files grew from %d to %d", before, after)
	}
}

func openFiles(t *testing.T) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("/proc/self/fd not available")
	}
	return len(entries)
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

func TestECDSAKeyFilesRejectedWithoutAgent(t *testing.T) {
	a := startAgent(t)
	key := a.createKey("ec-file@test", "ecdsa")
	a.addKey(key)
	for _, socket := range []string{a.socket, "/nonexistent/agent.sock"} {
		for _, selector := range []string{key, key + ".pub"} {
			armor, err := Encrypt([]byte("must not encrypt"), selector, &Options{AgentSocket: socket})
			if err == nil || !strings.HasPrefix(err.Error(), "Unsupported key type: ecdsa-sha2-") || armor != "" {
				t.Fatalf("%s %s: %q %v", socket, selector, armor, err)
			}
		}
	}
}

func TestDefaultKeyEnv(t *testing.T) {
	a := startAgent(t)
	first := a.createKey("first@test", "ed25519")
	preferred := a.createKey("preferred@test", "ed25519")
	a.addKey(first)
	a.addKey(preferred)
	a.addKey(filepath.Join(repoRoot, "test", "fixtures", "ed25519"))
	fingerprintOf := func(path string) string {
		return strings.Fields(string(a.run("ssh-keygen", nil, "-lf", path+".pub")))[1]
	}
	t.Setenv(DefaultKeyEnv, "preferred@test")

	armored, err := Encrypt([]byte("x"), "", a.options())
	if err != nil || !strings.Contains(armored, fingerprintOf(preferred)) {
		t.Fatalf("env key: %q %v", armored, err)
	}
	armored, err = Encrypt([]byte("x"), "first@test", a.options())
	if err != nil || !strings.Contains(armored, fingerprintOf(first)) {
		t.Fatalf("argument wins: %q %v", armored, err)
	}
	armored, err = Encrypt([]byte("x"), "", &Options{AgentSocket: a.socket, DefaultKey: "first@test"})
	if err != nil || !strings.Contains(armored, fingerprintOf(first)) {
		t.Fatalf("Options.DefaultKey wins over env: %q %v", armored, err)
	}
	// Embedded fingerprint wins over the env default when decrypting.
	toFirst, _ := Encrypt([]byte("for first"), "first@test", a.options())
	if got, err := Decrypt([]byte(toFirst), "", a.options()); err != nil || string(got) != "for first" {
		t.Fatalf("fingerprint wins: %q %v", got, err)
	}
	// v1 has no fingerprint: the env default selects the key.
	t.Setenv(DefaultKeyEnv, "fixture-ed25519@test")
	v1, _ := os.ReadFile(filepath.Join(repoRoot, "test", "fixtures", "v1.ed25519.txt"))
	if got, err := Decrypt(v1, "", a.options()); err != nil || string(got) != "legacy token" {
		t.Fatalf("v1 via env: %q %v", got, err)
	}
	// Fallback order: SSH_AGENT_CRYPT_KEY, VAUTH_USER_IDENTITY, VAUTH_USER_MAIL.
	t.Setenv(DefaultKeyEnv, "")
	t.Setenv("VAUTH_USER_MAIL", "preferred@test")
	if armored, err := Encrypt([]byte("x"), "", a.options()); err != nil || !strings.Contains(armored, fingerprintOf(preferred)) {
		t.Fatalf("VAUTH_USER_MAIL: %q %v", armored, err)
	}
	t.Setenv("VAUTH_USER_IDENTITY", "first@test")
	if armored, err := Encrypt([]byte("x"), "", a.options()); err != nil || !strings.Contains(armored, fingerprintOf(first)) {
		t.Fatalf("VAUTH_USER_IDENTITY beats MAIL: %q %v", armored, err)
	}
	t.Setenv(DefaultKeyEnv, "preferred@test")
	if armored, err := Encrypt([]byte("x"), "", a.options()); err != nil || !strings.Contains(armored, fingerprintOf(preferred)) {
		t.Fatalf("SSH_AGENT_CRYPT_KEY beats VAUTH: %q %v", armored, err)
	}
	t.Setenv(DefaultKeyEnv, "nobody@test")
	if _, err := Encrypt([]byte("x"), "", a.options()); err == nil || err.Error() != "Key not found: nobody@test" {
		t.Fatalf("missing env key: %v", err)
	}
}
