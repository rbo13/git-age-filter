package check

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rbo13/git-age-filter/internal/crypto"
	"github.com/rbo13/git-age-filter/internal/policy"
)

var (
	ErrCheckFailed = errors.New("check found policy violations")
	ErrConfig      = errors.New("check config error")
	ErrGit         = errors.New("check git error")
)

type Options struct {
	RepoPath   string
	ConfigPath string
}

type Result struct {
	ScannedFiles int
	Violations   []Violation
}

type Violation struct {
	Path   string
	Reason string
}

func Run(ctx context.Context, opts Options) (*Result, error) {
	repoPath, configPath, err := NormalizeOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	cfg, err := loadPolicy(configPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	files, err := trackedFiles(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGit, err)
	}

	result := &Result{}
	for _, file := range files {
		rule := cfg.Match(file)
		if rule == nil {
			continue
		}
		result.ScannedFiles++

		blob, err := ReadTrackedBlob(ctx, repoPath, file)
		if err != nil {
			result.Violations = append(result.Violations, Violation{
				Path:   file,
				Reason: fmt.Sprintf("unable to read git blob: %v", err),
			})
			continue
		}

		if !crypto.IsCiphertext(blob) {
			result.Violations = append(result.Violations, Violation{
				Path:   file,
				Reason: "tracked content is plaintext (not age ciphertext)",
			})
		}
	}

	if len(result.Violations) > 0 {
		return result, fmt.Errorf("%w: %d file(s) violated policy", ErrCheckFailed, len(result.Violations))
	}

	return result, nil
}

func NormalizeOptions(opts Options) (repoPath, configPath string, err error) {
	repoPath = strings.TrimSpace(opts.RepoPath)
	if repoPath == "" {
		repoPath, err = os.Getwd()
		if err != nil {
			return "", "", fmt.Errorf("resolve repository path: %w", err)
		}
	}

	configPath = strings.TrimSpace(opts.ConfigPath)
	if configPath == "" {
		configPath = filepath.Join(repoPath, ".agefilter.yaml")
	}
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(repoPath, configPath)
	}
	return repoPath, configPath, nil
}

func loadPolicy(configPath string) (*policy.File, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", configPath, err)
	}
	cfg, err := policy.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", configPath, err)
	}
	return cfg, nil
}

func trackedFiles(ctx context.Context, repoPath string) ([]string, error) {
	out, err := runGit(ctx, repoPath, "ls-files")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		files = append(files, trimmed)
	}
	return files, nil
}

func ReadTrackedBlob(ctx context.Context, repoPath, path string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", "show", ":"+path)
	cmd.Dir = repoPath
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err == nil {
		return output.Bytes(), nil
	}

	output.Reset()
	cmd = exec.CommandContext(ctx, "git", "show", "HEAD:"+path)
	cmd.Dir = repoPath
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git show failed for %q", path)
	}
	return output.Bytes(), nil
}

func runGit(ctx context.Context, repoPath string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repoPath
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(output.String()))
	}
	return output.String(), nil
}
