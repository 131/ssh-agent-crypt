package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCLIProcess(t *testing.T) {
	if os.Getenv("CRYPT_CLI_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"ssh-agent-crypt"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestCLIUsageMatchesNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--bad"}, {"-decrypt", "--bad"}, {"-decrypt", "a", "b"}, {"a", "b"}} {
		goArgs := append([]string{"-test.run=TestCLIProcess", "--"}, args...)
		goCmd := exec.Command(binary, goArgs...)
		goCmd.Env = append(os.Environ(), "CRYPT_CLI_TEST_PROCESS=1")
		goCmd.Stdin = bytes.NewBufferString("bad armor")
		nodeArgs := append([]string{filepath.Join(root, "bin", "ssh-agent-crypt.js")}, args...)
		nodeCmd := exec.Command(node, nodeArgs...)
		nodeCmd.Stdin = bytes.NewBufferString("bad armor")
		var gs, ge, ns, ne bytes.Buffer
		goCmd.Stdout = &gs
		goCmd.Stderr = &ge
		nodeCmd.Stdout = &ns
		nodeCmd.Stderr = &ne
		if err := goCmd.Run(); err == nil {
			t.Fatalf("Go accepted %v", args)
		}
		if err := nodeCmd.Run(); err == nil {
			t.Fatalf("Node accepted %v", args)
		}
		if !bytes.Equal(gs.Bytes(), ns.Bytes()) || !bytes.Equal(ge.Bytes(), ne.Bytes()) {
			t.Fatalf("CLI divergence %v\nGo: %q\nNode: %q", args, ge.String(), ne.String())
		}
	}
}
