package doctor_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/rbo13/git-age-filter/internal/doctor"
)

func TestRunSuccess(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	identity, recipient := makeIdentityPair(t)
	identityPath := filepath.Join(repo, "keys.txt")
	writeFile(t, identityPath, identity.String()+"\n")
	writePolicy(t, filepath.Join(repo, ".agefilter.yaml"), identityPath, recipient.String())

	runGitCmd(t, repo, "config", "--local", "filter.age.clean", "git-age-filter clean --path %f")
	runGitCmd(t, repo, "config", "--local", "filter.age.smudge", "git-age-filter smudge --path %f")
	runGitCmd(t, repo, "config", "--local", "filter.age.required", "true")

	result, err := doctor.Run(context.Background(), doctor.Options{
		RepoPath:   repo,
		ConfigPath: filepath.Join(repo, ".agefilter.yaml"),
	})
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if result == nil {
		t.Fatal("Run() returned nil result")
	}
	if len(result.Failures) != 0 {
		t.Fatalf("Run() unexpected failures: %#v", result.Failures)
	}
}

func TestRunFailsWhenFilterConfigMissing(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	identity, recipient := makeIdentityPair(t)
	identityPath := filepath.Join(repo, "keys.txt")
	writeFile(t, identityPath, identity.String()+"\n")
	writePolicy(t, filepath.Join(repo, ".agefilter.yaml"), identityPath, recipient.String())

	_, err := doctor.Run(context.Background(), doctor.Options{
		RepoPath:   repo,
		ConfigPath: filepath.Join(repo, ".agefilter.yaml"),
	})
	if err == nil {
		t.Fatal("Run() expected error when git filter config is missing; got nil")
	}
	if !errors.Is(err, doctor.ErrGit) {
		t.Fatalf("Run() error=%v; want ErrGit", err)
	}
}

func TestRunFailsWhenIdentityMissing(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	writeFile(t, filepath.Join(repo, ".agefilter.yaml"), `version: 1
defaults:
  armored: true
  on_missing_identity: fail
identities:
  - ./missing-keys.txt
rules:
  - path: "secrets/*.env"
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]
    required: true
`)

	runGitCmd(t, repo, "config", "--local", "filter.age.clean", "git-age-filter clean --path %f")
	runGitCmd(t, repo, "config", "--local", "filter.age.smudge", "git-age-filter smudge --path %f")
	runGitCmd(t, repo, "config", "--local", "filter.age.required", "true")

	_, err := doctor.Run(context.Background(), doctor.Options{
		RepoPath:   repo,
		ConfigPath: filepath.Join(repo, ".agefilter.yaml"),
	})
	if err == nil {
		t.Fatal("Run() expected error when identity file is missing; got nil")
	}
}

func TestRunConfigErrorMissingPolicy(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	_, err := doctor.Run(context.Background(), doctor.Options{
		RepoPath:   repo,
		ConfigPath: filepath.Join(repo, "missing.yaml"),
	})
	if !errors.Is(err, doctor.ErrConfig) {
		t.Fatalf("Run() error=%v; want ErrConfig", err)
	}
}

func TestNormalizeOptionsDefaults(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}

	repo, config, err := doctor.NormalizeOptions(doctor.Options{})
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

func TestExpandPathVariants(t *testing.T) {
	t.Parallel()

	repo := t.TempDir()
	abs, err := doctor.ExpandPath(repo, "/tmp/keys.txt")
	if err != nil {
		t.Fatalf("expandPath(abs) error: %v", err)
	}
	if abs != "/tmp/keys.txt" {
		t.Fatalf("expandPath(abs)=%q; want %q", abs, "/tmp/keys.txt")
	}

	rel, err := doctor.ExpandPath(repo, "keys.txt")
	if err != nil {
		t.Fatalf("expandPath(rel) error: %v", err)
	}
	if rel != filepath.Join(repo, "keys.txt") {
		t.Fatalf("expandPath(rel)=%q; want repo-relative", rel)
	}
}

func TestCheckIdentityFilesNoPaths(t *testing.T) {
	t.Parallel()

	err := doctor.CheckIdentityFiles(t.TempDir(), nil)
	if err == nil {
		t.Fatal("checkIdentityFiles() expected error for empty paths")
	}
}

func TestRunWarnsOnBroadIdentityPermissions(t *testing.T) {
	t.Parallel()

	repo := initRepo(t)
	identity, recipient := makeIdentityPair(t)
	identityPath := filepath.Join(repo, "keys.txt")
	if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	writePolicy(t, filepath.Join(repo, ".agefilter.yaml"), identityPath, recipient.String())

	runGitCmd(t, repo, "config", "--local", "filter.age.clean", "git-age-filter clean --path %f")
	runGitCmd(t, repo, "config", "--local", "filter.age.smudge", "git-age-filter smudge --path %f")
	runGitCmd(t, repo, "config", "--local", "filter.age.required", "true")

	result, err := doctor.Run(context.Background(), doctor.Options{
		RepoPath:   repo,
		ConfigPath: filepath.Join(repo, ".agefilter.yaml"),
	})
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("Run() expected warning for broad identity file permissions")
	}
}

func TestCheckIdentityFilesRejectsURLPath(t *testing.T) {
	t.Parallel()

	err := doctor.CheckIdentityFiles(t.TempDir(), []string{"https://example.com/keys.txt"})
	if err == nil {
		t.Fatal("checkIdentityFiles() expected error for URL path")
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error: %v", path, err)
	}
}

func makeIdentityPair(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error: %v", err)
	}
	return id, id.Recipient()
}

func writePolicy(t *testing.T, path, identityPath, recipient string) {
	t.Helper()
	writeFile(t, path, fmt.Sprintf(`version: 1
defaults:
  armored: true
  on_missing_identity: fail
identities:
  - %q
rules:
  - path: "secrets/*.env"
    recipients: [%q]
    required: true
`, identityPath, recipient))
}
