package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

var (
	ErrNotGitRepository = errors.New("not a git repository")
	ErrGitCommandFailed = errors.New("git command failed")
)

type Client struct {
	repoPath string
}

func NewClient(repoPath string) *Client {
	return &Client{repoPath: repoPath}
}

func (c *Client) ConfigureFilter(ctx context.Context, binary string) error {
	if strings.TrimSpace(binary) == "" {
		binary = "git-age-filter"
	}

	commands := [][]string{
		{"config", "--local", "filter.age.clean", fmt.Sprintf("%s clean --path %%f", binary)},
		{"config", "--local", "filter.age.smudge", fmt.Sprintf("%s smudge --path %%f", binary)},
		{"config", "--local", "filter.age.required", "true"},
	}
	for _, args := range commands {
		if _, err := c.runGit(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) EnsureAttributes(ctx context.Context, patterns []string) error {
	path := filepath.Join(c.repoPath, ".gitattributes")
	existing := []string{}

	content, err := os.ReadFile(path)
	switch {
	case err == nil:
		existing = splitNonEmptyLines(string(content))
	case errors.Is(err, os.ErrNotExist):
	default:
		return fmt.Errorf("read .gitattributes: %w", err)
	}

	updated := slices.Clone(existing)
	for _, pattern := range patterns {
		p := strings.TrimSpace(pattern)
		if p == "" {
			continue
		}
		line := fmt.Sprintf("%s filter=age diff=age merge=binary -text", p)
		if !slices.Contains(updated, line) {
			updated = append(updated, line)
		}
	}

	data := strings.Join(updated, "\n")
	if data != "" {
		data += "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		return fmt.Errorf("write .gitattributes: %w", err)
	}
	return nil
}

func (c *Client) runGit(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = c.repoPath
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		text := strings.TrimSpace(output.String())
		if strings.Contains(text, "not a git repository") || strings.Contains(text, "can only be used inside a git repository") {
			return "", ErrNotGitRepository
		}
		return "", fmt.Errorf("%w: git %s: %s", ErrGitCommandFailed, strings.Join(args, " "), text)
	}

	return strings.TrimSpace(output.String()), nil
}

func splitNonEmptyLines(content string) []string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
