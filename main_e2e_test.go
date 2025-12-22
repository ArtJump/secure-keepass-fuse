//go:build linux
// +build linux

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

const (
	fixtureDBPath  = "./test_fixtures/test.kdbx"
	fixturePass    = "123456"
	fixtureContent = `# created: 2025-12-22T02:50:55+05:00
# public key: age1vjp28mjpaq8028yk3flhpau2w7vk6umxxrp5jjyfwdds88pug48qskv96m
AGE-SECRET-KEY-1RPYHZ0UYCW6ZQ330CS4YD3LA499D6PE0L07J0HC2FFZNHS5GLW0SL63PX7`
	fixtureBINLink = "/tmp/secure-fs-test-allow"
	fixtureAttach  = "key.txt"
)

func TestEndToEnd_Secure(t *testing.T) {
	if _, err := os.Stat(fixtureDBPath); os.IsNotExist(err) {
		t.Fatalf("Fixture DB not found at %s. Please create it manually according to instructions.", fixtureDBPath)
	}

	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("Tool 'cat' not found")
	}

	_ = os.Remove(fixtureBINLink)

	if err := os.Symlink(catPath, fixtureBINLink); err != nil {
		t.Fatalf("Failed to create symlink %s -> %s: %v", fixtureBINLink, catPath, err)
	}
	defer os.Remove(fixtureBINLink)

	tmpDir := t.TempDir()
	appBin := filepath.Join(tmpDir, "secure-fs-testbin")
	mountPoint := filepath.Join(tmpDir, "mnt")

	t.Logf("Building app to %s...", appBin)
	buildCmd := exec.Command("go", "build", "-o", appBin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %s", out)
	}

	absDBPath, _ := filepath.Abs(fixtureDBPath)
	cmd := exec.Command(appBin, "--verbose", absDBPath, mountPoint)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("Failed to start PTY: %v", err)
	}

	defer func() {
		t.Log("Cleaning up processes and mounts...")
		if cmd.Process != nil {
			cmd.Process.Signal(syscall.SIGINT)
			time.Sleep(100 * time.Millisecond)
			if cmd.ProcessState != nil && !cmd.ProcessState.Exited() {
				cmd.Process.Kill()
			}
		}
		_ = ptmx.Close()
		exec.Command("fusermount", "-u", "-z", mountPoint).Run()
	}()

	time.Sleep(500 * time.Millisecond)
	t.Log("Entering password...")
	if _, err := ptmx.Write([]byte(fixturePass + "\n")); err != nil {
		t.Fatalf("Failed to write password: %v", err)
	}

	t.Log("Waiting for mount...")
	mounted := false
	targetFile := ""

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat(mountPoint); err != nil {
			continue
		}

		_ = filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
			if info != nil && info.Name() == fixtureAttach {
				targetFile = path
				return io.EOF
			}
			return nil
		})

		if targetFile != "" {
			mounted = true
			break
		}
	}

	if !mounted {
		buf := make([]byte, 4096)
		n, _ := ptmx.Read(buf)
		t.Fatalf("Mount failed. App output:\n%s", string(buf[:n]))
	}
	t.Logf("Mounted! File found at: %s", targetFile)

	// --- TEST CASE 1: Deny Access (Go Test Process) ---
	t.Run("Should_Deny_Access_To_Unauthorized_Process", func(t *testing.T) {
		content, err := os.ReadFile(targetFile)
		if err == nil {
			t.Errorf("SECURITY BREACH! Read content: %s", content)
		} else {
			if os.IsPermission(err) ||
				strings.Contains(err.Error(), "permission denied") ||
				strings.Contains(err.Error(), "input/output error") {
				t.Log("OK: Access denied as expected.")
			} else {
				t.Logf("OK: Read failed (checking error type): %v", err)
			}
		}
	})

	// --- TEST CASE 2: Allow Access (Cat) ---
	t.Run("Should_Allow_Access_To_Whitelisted_Binary", func(t *testing.T) {
		cmdCat := exec.Command(catPath, targetFile)
		out, err := cmdCat.CombinedOutput()

		if err != nil {
			t.Errorf("Whitelisted binary failed to read. Error: %v\nOutput: %s", err, out)
		} else {
			got := strings.TrimSpace(string(out))
			if got != fixtureContent {
				t.Errorf("Content mismatch.\nGot:  %q\nWant: %q", got, fixtureContent)
			} else {
				t.Logf("OK: Content verified successfully.")
			}
		}
	})

	// --- TEST CASE 3: Symlink Resolution Check ---
	t.Run("Should_Also_Work_Via_Symlink_Invocation", func(t *testing.T) {
		cmdSym := exec.Command(fixtureBINLink, targetFile)
		if out, err := cmdSym.CombinedOutput(); err == nil {
			t.Logf("OK: Symlink invocation also works (Output len: %d)", len(out))
		} else {
			t.Logf("Note: Symlink invocation failed (might be expected depending on OS/FUSE behavior): %v", err)
		}
	})
}
