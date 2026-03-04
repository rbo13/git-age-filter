package git_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbo13/git-age-filter/internal/git"
)

func TestConfigureFilter(t *testing.T) {
	t.Parallel()

	repo := initTempRepo(t)
	client := git.NewClient(repo)

	err := client.ConfigureFilter(context.Background(), "git-age-filter")
	if err != nil {
		t.Fatalf("ConfigureFilter() returned error: %v", err)
	}

	assertGitConfigValue(t, repo, "filter.age.clean", "git-age-filter clean --path %f")
	assertGitConfigValue(t, repo, "filter.age.smudge", "git-age-filter smudge --path %f")
	assertGitConfigValue(t, repo, "filter.age.required", "true")
}

func TestEnsureAttributesIdempotent(t *testing.T) {
	t.Parallel()

	repo := initTempRepo(t)
	client := NewClient(repo)

	patterns := []string{"secrets/*.env", "infra/prod/*.yaml"}
	if err := client.EnsureAttributes(context.Background(), patterns); err != nil {
		t.Fatalf("EnsureAttributes() returned error: %v", err)
	}
	if err := client.EnsureAttributes(context.Background(), patterns); err != nil {
		t.Fatalf("EnsureAttributes() second run returned error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(repo, ".gitattributes"))
	if err != nil {
		t.Fatalf("ReadFile(.gitattributes) error: %v", err)
	}

	text := string(content)
	for _, pattern := range patterns {
		line := pattern + " filter=age diff=age merge=binary -text"
		if count := strings.Count(text, line); count != 1 {
			t.Fatalf("line %q count = %d; want 1", line, count)
		}
	}
}

func TestConfigureFilterOutsideGitRepository(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	client := NewClient(dir)

	err := client.ConfigureFilter(context.Background(), "git-age-filter")
	if !errors.Is(err, ErrNotGitRepository) {
		t.Fatalf("ConfigureFilter() error = %v; want ErrNotGitRepository", err)
	}
}

func initTempRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init error: %v, output: %s", err, output)
	}

	return dir
}

func assertGitConfigValue(t *testing.T, repoPath, key, want string) {
	t.Helper()

	cmd := exec.Command("git", "config", "--local", "--get", key)
	cmd.Dir = repoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git config --get %s error: %v, output: %s", key, err, output)
	}

	got := strings.TrimSpace(string(output))
	if got != want {
		t.Fatalf("git config %s = %q; want %q", key, got, want)
	}
}
