package policy

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/rbo13/git-age-filter/internal/crypto"
	"gopkg.in/yaml.v3"
)

const (
	OnMissingIdentityFail = "fail"
	OnMissingIdentityPass = "pass"
	DefaultMaxFileSize    = 10 * 1024 * 1024
)

type File struct {
	Version       int                 `yaml:"version"`
	Defaults      Defaults            `yaml:"defaults"`
	Identities    []string            `yaml:"identities"`
	RecipientSets map[string][]string `yaml:"recipient_sets"`
	Rules         []Rule              `yaml:"rules"`
}

type Defaults struct {
	Armored           bool   `yaml:"armored"`
	MaxFileSize       int64  `yaml:"max_file_size"`
	OnMissingIdentity string `yaml:"on_missing_identity"`
}

type Rule struct {
	Path       string   `yaml:"path"`
	Recipients []string `yaml:"recipients"`
	Armored    *bool    `yaml:"armored,omitempty"`
	Required   bool     `yaml:"required"`
}

func Parse(raw []byte) (*File, error) {
	var got File
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	if err := decoder.Decode(&got); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("parse policy yaml: empty document")
		}
		return nil, fmt.Errorf("parse policy yaml: %w", err)
	}

	var extraDoc yaml.Node
	if err := decoder.Decode(&extraDoc); err != nil && err != io.EOF {
		return nil, fmt.Errorf("parse policy yaml: %w", err)
	}
	if len(extraDoc.Content) != 0 || extraDoc.Kind != 0 {
		return nil, fmt.Errorf("parse policy yaml: multiple documents are not supported")
	}

	if err := got.Validate(); err != nil {
		return nil, err
	}

	return &got, nil
}

func (f *File) Validate() error {
	if f.Version != 1 {
		return fmt.Errorf("policy version must be 1")
	}

	if len(f.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}

	if f.Defaults.OnMissingIdentity == "" {
		f.Defaults.OnMissingIdentity = OnMissingIdentityFail
	}

	if f.Defaults.OnMissingIdentity != OnMissingIdentityFail && f.Defaults.OnMissingIdentity != OnMissingIdentityPass {
		return fmt.Errorf("defaults.on_missing_identity must be fail or pass")
	}
	if f.Defaults.MaxFileSize <= 0 {
		f.Defaults.MaxFileSize = DefaultMaxFileSize
	}

	if f.RecipientSets == nil {
		f.RecipientSets = map[string][]string{}
	}

	for i := range f.Rules {
		normalizedPath, err := NormalizeRulePath(f.Rules[i].Path)
		if err != nil {
			return fmt.Errorf("rules[%d].path: %w", i, err)
		}
		f.Rules[i].Path = normalizedPath

		if len(f.Rules[i].Recipients) == 0 {
			return fmt.Errorf("rules[%d].recipients must not be empty", i)
		}

		resolved, err := f.ResolvedRecipients(f.Rules[i])
		if err != nil {
			return fmt.Errorf("rules[%d].recipients: %w", i, err)
		}
		if len(resolved) == 0 {
			return fmt.Errorf("rules[%d].recipients resolve to empty list", i)
		}

		for j, recipient := range resolved {
			if _, err := crypto.ParseRecipient(recipient); err != nil {
				return fmt.Errorf("rules[%d].recipients[%d]: invalid recipient", i, j)
			}
		}
	}

	return nil
}

func (f *File) Match(relPath string) *Rule {
	normalizedPath := normalizeInputPath(relPath)
	if normalizedPath == "" {
		return nil
	}

	var matched *Rule
	for i := range f.Rules {
		if doublestarMatch(f.Rules[i].Path, normalizedPath) {
			rule := f.Rules[i]
			matched = &rule
		}
	}

	return matched
}

func (f *File) ResolvedRecipients(rule Rule) ([]string, error) {
	recipients := make([]string, 0, len(rule.Recipients))
	seen := make(map[string]struct{}, len(rule.Recipients))

	for _, entry := range rule.Recipients {
		item := strings.TrimSpace(entry)
		if item == "" {
			return nil, fmt.Errorf("recipient entry is empty")
		}

		if set, ok := f.RecipientSets[item]; ok {
			for _, setEntry := range set {
				resolved := strings.TrimSpace(setEntry)
				if resolved == "" {
					continue
				}
				if _, exists := seen[resolved]; exists {
					continue
				}
				seen[resolved] = struct{}{}
				recipients = append(recipients, resolved)
			}
			continue
		}

		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		recipients = append(recipients, item)
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients resolved")
	}

	return recipients, nil
}

func NormalizeRulePath(rulePath string) (string, error) {
	p := strings.TrimSpace(rulePath)
	if p == "" {
		return "", fmt.Errorf("must not be empty")
	}

	p = strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("must be repository-relative")
	}
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("must be repository-relative")
	}
	if len(p) >= 2 && p[1] == ':' {
		return "", fmt.Errorf("must be repository-relative")
	}

	for _, segment := range strings.Split(p, "/") {
		if segment == ".." {
			return "", fmt.Errorf("must not traverse parent directories")
		}
	}

	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("must not be empty")
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", fmt.Errorf("must not traverse parent directories")
	}

	return cleaned, nil
}

func normalizeInputPath(repoPath string) string {
	p := strings.TrimSpace(repoPath)
	if p == "" {
		return ""
	}

	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}

	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}

func doublestarMatch(pattern, relPath string) bool {
	return matchSegments(splitPath(pattern), splitPath(relPath))
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func matchSegments(patternParts, pathParts []string) bool {
	if len(patternParts) == 0 {
		return len(pathParts) == 0
	}

	if patternParts[0] == "**" {
		if matchSegments(patternParts[1:], pathParts) {
			return true
		}
		if len(pathParts) == 0 {
			return false
		}
		return matchSegments(patternParts, pathParts[1:])
	}

	if len(pathParts) == 0 {
		return false
	}

	matched, err := path.Match(patternParts[0], pathParts[0])
	if err != nil || !matched {
		return false
	}

	return matchSegments(patternParts[1:], pathParts[1:])
}
