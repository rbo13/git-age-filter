package check_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/rbo13/git-age-filter/internal/check"
	"github.com/rbo13/git-age-filter/internal/crypto"
)

func TestRunSuccessWithEncryptedProtectedFile(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	_, recipient := identityPair(t)
	configPath := filepath.Join(repo, ".agefilter.yaml")
	writePolicy(t, configPath, recipient.String())

	var cipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewBufferString("SECRET=VALUE\n"), &cipher, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
		Armored:    true,
	})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	protected := filepath.Join(repo, "secrets", "app.env")
	if err := os.MkdirAll(filepath.Dir(protected), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(protected, cipher.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	runGitCmd(t, repo, "add", "secrets/app.env")

	result, err := check.Run(context.Background(), check.Options{
		RepoPath:   repo,
		ConfigPath: configPath,
	})
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if result == nil || result.ScannedFiles == 0 {
		t.Fatalf("Run() result=%#v; expected scanned files", result)
	}
}

func TestRunFailsOnPlaintextProtectedFile(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	_, recipient := identityPair(t)
	configPath := filepath.Join(repo, ".agefilter.yaml")
	writePolicy(t, configPath, recipient.String())

	protected := filepath.Join(repo, "secrets", "app.env")
	if err := os.MkdirAll(filepath.Dir(protected), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(protected, []byte("SECRET=VALUE\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	runGitCmd(t, repo, "add", "secrets/app.env")

	_, err := check.Run(context.Background(), check.Options{
		RepoPath:   repo,
		ConfigPath: configPath,
	})
	if err == nil {
		t.Fatal("Run() expected error for plaintext protected file; got nil")
	}
}

func TestRunIgnoresNonMatchingTrackedFiles(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	_, recipient := identityPair(t)
	configPath := filepath.Join(repo, ".agefilter.yaml")
	writePolicy(t, configPath, recipient.String())

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	runGitCmd(t, repo, "add", "README.md")

	result, err := check.Run(context.Background(), check.Options{
		RepoPath:   repo,
		ConfigPath: configPath,
	})
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if result.ScannedFiles != 0 {
		t.Fatalf("ScannedFiles=%d; want 0", result.ScannedFiles)
	}
}

func TestRunConfigErrorMissingPolicy(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	_, err := check.Run(context.Background(), check.Options{
		RepoPath:   repo,
		ConfigPath: filepath.Join(repo, "missing.yaml"),
	})
	if !errors.Is(err, check.ErrConfig) {
		t.Fatalf("Run() error=%v; want ErrConfig", err)
	}
}

func TestNormalizeOptionsDefaults(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	repo, config, err := check.NormalizeOptions(check.Options{})
	if err != nil {
		t.Fatalf("normalizeOptions() error: %v", err)
	}
	if repo != wd {
		t.Fatalf("repo=%q; want %q", repo, wd)
	}
	if config != filepath.Join(wd, ".agefilter.yaml") {
		t.Fatalf("config=%q; want default path", config)
	}
}

func TestReadTrackedBlobFallbackToHead(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	runGitCmd(t, repo, "config", "user.name", "test")
	runGitCmd(t, repo, "config", "user.email", "test@example.com")

	if err := os.MkdirAll(filepath.Join(repo, "secrets"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	target := filepath.Join(repo, "secrets", "app.env")
	if err := os.WriteFile(target, []byte("v1"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	runGitCmd(t, repo, "add", "secrets/app.env")
	runGitCmd(t, repo, "commit", "-m", "add file")
	runGitCmd(t, repo, "rm", "--cached", "secrets/app.env")

	blob, err := check.ReadTrackedBlob(context.Background(), repo, "secrets/app.env")
	if err != nil {
		t.Fatalf("readTrackedBlob() returned error: %v", err)
	}
	if string(blob) != "v1" {
		t.Fatalf("readTrackedBlob()=%q; want %q", string(blob), "v1")
	}
}

func TestReadTrackedBlobError(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	_, err := check.ReadTrackedBlob(context.Background(), repo, "missing.env")
	if err == nil {
		t.Fatal("readTrackedBlob() expected error for missing file")
	}
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGitCmd(t, dir, "init")
	return dir
}

func runGitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v, output=%s", strings.Join(args, " "), err, out)
	}
}

func identityPair(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error: %v", err)
	}
	return id, id.Recipient()
}

func writePolicy(t *testing.T, path, recipient string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`version: 1
defaults:
  armored: true
  on_missing_identity: fail
rules:
  - path: "secrets/*.env"
    recipients: [%q]
    required: true
`, recipient)), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
}
