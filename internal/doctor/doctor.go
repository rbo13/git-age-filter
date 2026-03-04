package doctor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/rbo13/git-age-filter/internal/crypto"
	"github.com/rbo13/git-age-filter/internal/policy"
)

var (
	ErrDoctorFailed = errors.New("doctor checks failed")
	ErrConfig       = errors.New("doctor config error")
	ErrGit          = errors.New("doctor git error")
)

type Options struct {
	RepoPath   string
	ConfigPath string
}

type Result struct {
	Failures []string
	Warnings []string
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

	result := &Result{}
	gitFailures := false

	if err := checkGitRepository(ctx, repoPath); err != nil {
		result.Failures = append(result.Failures, fmt.Sprintf("git repository: %v", err))
		gitFailures = true
	} else {
		if err := checkGitFilterConfig(ctx, repoPath); err != nil {
			result.Failures = append(result.Failures, err.Error())
			gitFailures = true
		}
	}

	if err := CheckIdentityFiles(repoPath, cfg.Identities); err != nil {
		result.Failures = append(result.Failures, err.Error())
	}
	if warnings, err := checkIdentityFilesPermissions(repoPath, cfg.Identities); err != nil {
		result.Failures = append(result.Failures, err.Error())
	} else {
		result.Warnings = append(result.Warnings, warnings...)
	}

	if err := checkRecipients(cfg); err != nil {
		result.Failures = append(result.Failures, err.Error())
	}
	if err := checkDryRunCrypto(); err != nil {
		result.Failures = append(result.Failures, err.Error())
	}

	if len(result.Failures) > 0 {
		if gitFailures {
			return result, fmt.Errorf("%w: %s", ErrGit, strings.Join(result.Failures, "; "))
		}
		return result, fmt.Errorf("%w: %s", ErrDoctorFailed, strings.Join(result.Failures, "; "))
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

func ExpandPath(repoPath, path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}

	if filepath.IsAbs(path) {
		return path, nil
	}
	return filepath.Join(repoPath, path), nil
}

func CheckIdentityFiles(repoPath string, paths []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("no identity paths configured")
	}

	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if strings.Contains(p, "://") || strings.HasPrefix(p, "age-plugin:") {
			return fmt.Errorf("identity path must be local filesystem path")
		}

		expanded, err := ExpandPath(repoPath, p)
		if err != nil {
			return fmt.Errorf("resolve identity path %q: %w", p, err)
		}

		if _, err := os.Stat(expanded); err != nil {
			return fmt.Errorf("identity path %q is not readable: %w", expanded, err)
		}

		if _, err := crypto.ParseIdentities([]string{expanded}); err != nil {
			return fmt.Errorf("identity path %q is not parseable", expanded)
		}
	}

	return nil
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

func checkGitRepository(ctx context.Context, repoPath string) error {
	out, err := runGit(ctx, repoPath, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGit, err)
	}
	if strings.TrimSpace(out) != "true" {
		return fmt.Errorf("%w: repository check returned %q", ErrGit, out)
	}
	return nil
}

func checkGitFilterConfig(ctx context.Context, repoPath string) error {
	clean, err := runGit(ctx, repoPath, "config", "--local", "--get", "filter.age.clean")
	if err != nil {
		return fmt.Errorf("git config filter.age.clean missing: %w", err)
	}
	if !strings.Contains(clean, "clean --path %f") {
		return fmt.Errorf("git config filter.age.clean unexpected value: %q", clean)
	}

	smudge, err := runGit(ctx, repoPath, "config", "--local", "--get", "filter.age.smudge")
	if err != nil {
		return fmt.Errorf("git config filter.age.smudge missing: %w", err)
	}
	if !strings.Contains(smudge, "smudge --path %f") {
		return fmt.Errorf("git config filter.age.smudge unexpected value: %q", smudge)
	}

	required, err := runGit(ctx, repoPath, "config", "--local", "--get", "filter.age.required")
	if err != nil {
		return fmt.Errorf("git config filter.age.required missing: %w", err)
	}
	if strings.TrimSpace(required) != "true" {
		return fmt.Errorf("git config filter.age.required should be true, got %q", required)
	}

	return nil
}

func checkIdentityFilesPermissions(repoPath string, paths []string) ([]string, error) {
	warnings := make([]string, 0)

	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if strings.Contains(p, "://") || strings.HasPrefix(p, "age-plugin:") {
			return nil, fmt.Errorf("identity path must be local filesystem path")
		}
		expanded, err := ExpandPath(repoPath, p)
		if err != nil {
			return nil, fmt.Errorf("resolve identity path %q: %w", p, err)
		}
		info, err := os.Stat(expanded)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0o077 != 0 {
			warnings = append(warnings, fmt.Sprintf("identity path %q has broad permissions (%#o)", expanded, info.Mode().Perm()))
		}
	}

	return warnings, nil
}

func checkRecipients(cfg *policy.File) error {
	for i, rule := range cfg.Rules {
		resolved, err := cfg.ResolvedRecipients(rule)
		if err != nil {
			return fmt.Errorf("rule %d recipients invalid", i)
		}
		for _, recipient := range resolved {
			if _, err := crypto.ParseRecipient(recipient); err != nil {
				return fmt.Errorf("rule %d contains invalid recipient", i)
			}
		}
	}
	return nil
}

func checkDryRunCrypto() error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("dry-run: generate identity: %w", err)
	}
	recipient := identity.Recipient()

	payload := []byte("doctor-dry-run")
	var cipher bytes.Buffer
	encryptWriter, err := age.Encrypt(&cipher, recipient)
	if err != nil {
		return fmt.Errorf("dry-run: encrypt writer: %w", err)
	}
	if _, err := encryptWriter.Write(payload); err != nil {
		return fmt.Errorf("dry-run: encrypt payload: %w", err)
	}
	if err := encryptWriter.Close(); err != nil {
		return fmt.Errorf("dry-run: close encrypt writer: %w", err)
	}

	decryptReader, err := age.Decrypt(bytes.NewReader(cipher.Bytes()), identity)
	if err != nil {
		return fmt.Errorf("dry-run: decrypt reader: %w", err)
	}
	plain, err := io.ReadAll(decryptReader)
	if err != nil {
		return fmt.Errorf("dry-run: read decrypted payload: %w", err)
	}
	if !bytes.Equal(plain, payload) {
		return fmt.Errorf("dry-run: decrypted payload mismatch")
	}
	return nil
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
	return strings.TrimSpace(output.String()), nil
}
