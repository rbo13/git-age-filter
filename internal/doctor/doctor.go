package doctor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rbo13/git-age-filter/internal/crypto"
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
	return nil, nil
}

func NormalizeOptions(opts Options) (repoPath, configPath string, err error) {
	return "", "", nil
}

func ExpandPath(repoPath, path string) (string, error) {
	return "", nil
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
