package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rbo13/git-age-filter/internal/check"
	"github.com/rbo13/git-age-filter/internal/crypto"
	"github.com/rbo13/git-age-filter/internal/exitcode"
	"github.com/rbo13/git-age-filter/internal/filter"
	"github.com/rbo13/git-age-filter/internal/git"
	"github.com/rbo13/git-age-filter/internal/policy"
	"github.com/rbo13/git-age-filter/internal/version"
)

type globalOptions struct {
	configPath string
	verbose    bool
	noColor    bool
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: git-age-filter <command> [flags]")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  init      Configure git filter and policy scaffold")
	fmt.Fprintln(w, "  clean     Git clean filter entrypoint")
	fmt.Fprintln(w, "  smudge    Git smudge filter entrypoint")
	fmt.Fprintln(w, "  encrypt   Encrypt a file manually")
	fmt.Fprintln(w, "  decrypt   Decrypt a file manually")
	fmt.Fprintln(w, "  doctor    Validate environment and setup")
	fmt.Fprintln(w, "  check     CI policy verification")
	fmt.Fprintln(w, "  version   Print version")
	fmt.Fprintln(w, "  help      Show help")
}

var implementedCommands = map[string]func(context.Context, io.Writer, io.Writer) int{
	"help": func(_ context.Context, stdout io.Writer, _ io.Writer) int {
		printUsage(stdout)
		return exitcode.Success
	},
	"version": func(_ context.Context, stdout io.Writer, _ io.Writer) int {
		fmt.Fprintf(stdout, "git-age-filter %s\n", version.Value)
		return exitcode.Success
	},
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitcode.UsageError
	}

	opts, command, commandArgs, err := parseGlobalOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "invalid global flags: %v\n", err)
		printUsage(stderr)
		return exitcode.UsageError
	}

	if command == "" {
		printUsage(stderr)
		return exitcode.UsageError
	}

	if command == "-h" || command == "--help" {
		printUsage(stdout)
		return exitcode.Success
	}

	if handler, ok := implementedCommands[command]; ok {
		return handler(ctx, stdout, stderr)
	}

	switch command {
	case "init":
		return runInit(ctx, commandArgs, stdout, stderr, opts)
	case "clean":
		return runClean(ctx, commandArgs, stdout, stderr, opts)
	case "smudge":
		return runSmudge(ctx, commandArgs, stdout, stderr, opts)
	case "encrypt":
		return runEncrypt(ctx, commandArgs, stdout, stderr, opts)
	case "decrypt":
		return runDecrypt(ctx, commandArgs, stdout, stderr, opts)
	case "doctor":
		return runDoctor(ctx, commandArgs, stdout, stderr, opts)
	case "check":
		return runCheck(ctx, commandArgs, stdout, stderr, opts)
	}

	fmt.Fprintf(stderr, "unknown command %q\n", command)
	printUsage(stderr)
	return exitcode.UsageError
}

func parseGlobalOptions(args []string) (globalOptions, string, []string, error) {
	opts := globalOptions{
		configPath: ".agefilter.yaml",
	}
	if len(args) == 0 {
		return opts, "", nil, fmt.Errorf("no command provided")
	}

	i := 0
	for i < len(args) {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			i++
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			return opts, arg, args[i+1:], nil
		}

		switch {
		case arg == "--verbose":
			opts.verbose = true
		case arg == "--no-color":
			opts.noColor = true
		case strings.HasPrefix(arg, "--config="):
			opts.configPath = strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
			if opts.configPath == "" {
				return opts, "", nil, fmt.Errorf("--config requires a value")
			}
		case arg == "--config":
			if i+1 >= len(args) {
				return opts, "", nil, fmt.Errorf("--config requires a value")
			}
			i++
			opts.configPath = strings.TrimSpace(args[i])
			if opts.configPath == "" {
				return opts, "", nil, fmt.Errorf("--config requires a value")
			}
		case arg == "-h" || arg == "--help":
			return opts, arg, nil, nil
		default:
			return opts, "", nil, fmt.Errorf("unsupported global flag %q", arg)
		}

		i++
	}

	return opts, "", nil, fmt.Errorf("no command provided")
}

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer, global globalOptions) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", global.configPath, "policy file path")
	force := fs.Bool("force", false, "overwrite existing template config")
	if err := fs.Parse(args); err != nil {
		return exitcode.UsageError
	}

	if err := ensurePolicyTemplate(*configPath, *force); err != nil {
		fmt.Fprintf(stderr, "init config: %v\n", err)
		return exitcode.ConfigError
	}

	cfg, err := loadPolicy(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load policy: %v\n", err)
		return exitcode.ConfigError
	}

	repoPath, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "resolve working directory: %v\n", err)
		return exitcode.UnexpectedError
	}

	client := git.NewClient(repoPath)
	if err := client.ConfigureFilter(ctx, "git-age-filter"); err != nil {
		fmt.Fprintf(stderr, "configure git filter: %v\n", err)
		if errors.Is(err, git.ErrNotGitRepository) || errors.Is(err, git.ErrGitCommandFailed) {
			return exitcode.GitError
		}
		return exitcode.UnexpectedError
	}

	patterns := make([]string, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		patterns = append(patterns, rule.Path)
	}
	if err := client.EnsureAttributes(ctx, patterns); err != nil {
		fmt.Fprintf(stderr, "configure .gitattributes: %v\n", err)
		return exitcode.GitError
	}

	fmt.Fprintf(stdout, "initialized git-age-filter with %d protected pattern(s)\n", len(patterns))
	return exitcode.Success
}

func runClean(_ context.Context, args []string, stdout, stderr io.Writer, global globalOptions) int {
	fs := flag.NewFlagSet("clean", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", global.configPath, "policy file path")
	path := fs.String("path", "", "repository-relative path")
	if err := fs.Parse(args); err != nil {
		return exitcode.UsageError
	}
	if strings.TrimSpace(*path) == "" {
		fmt.Fprintln(stderr, "clean: --path is required")
		return exitcode.UsageError
	}

	cfg, err := loadPolicy(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load policy: %v\n", err)
		return exitcode.ConfigError
	}

	if err := filter.Clean(filter.CleanRequest{
		Path:   *path,
		Input:  os.Stdin,
		Policy: cfg,
	}, stdout); err != nil {
		fmt.Fprintf(stderr, "clean %s: %v\n", *path, err)
		if errors.Is(err, filter.ErrFileTooLarge) {
			return exitcode.PolicyViolation
		}
		return exitcode.CryptoError
	}

	return exitcode.Success
}

func runSmudge(_ context.Context, args []string, stdout, stderr io.Writer, global globalOptions) int {
	fs := flag.NewFlagSet("smudge", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", global.configPath, "policy file path")
	path := fs.String("path", "", "repository-relative path")
	if err := fs.Parse(args); err != nil {
		return exitcode.UsageError
	}
	if strings.TrimSpace(*path) == "" {
		fmt.Fprintln(stderr, "smudge: --path is required")
		return exitcode.UsageError
	}

	cfg, err := loadPolicy(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load policy: %v\n", err)
		return exitcode.ConfigError
	}

	if err := filter.Smudge(filter.SmudgeRequest{
		Path:   *path,
		Input:  os.Stdin,
		Policy: cfg,
	}, stdout); err != nil {
		if errors.Is(err, filter.ErrRequiredPathNotEncrypted) {
			fmt.Fprintf(stderr, "smudge %s: %v\n", *path, err)
			return exitcode.PolicyViolation
		}
		fmt.Fprintf(stderr, "smudge %s: %v\n", *path, err)
		return exitcode.CryptoError
	}

	return exitcode.Success
}

func runEncrypt(_ context.Context, args []string, stdout, stderr io.Writer, global globalOptions) int {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", global.configPath, "policy file path")
	inPath := fs.String("in", "", "input file path")
	outPath := fs.String("out", "", "output file path")
	ruleSelector := fs.String("rule", "", "rule selector (rule path or sample file path)")
	var armored boolFlag
	fs.Var(&armored, "armor", "write armored output (bool)")
	var recipients csvListFlag
	fs.Var(&recipients, "recipient", "recipient list (repeatable or comma-separated)")
	if err := fs.Parse(args); err != nil {
		return exitcode.UsageError
	}
	if strings.TrimSpace(*inPath) == "" || strings.TrimSpace(*outPath) == "" {
		fmt.Fprintln(stderr, "encrypt: --in and --out are required")
		return exitcode.UsageError
	}
	finalRecipients := []string(recipients)
	selectedRule, cfg, err := resolveRuleForEncrypt(*configPath, *ruleSelector)
	if err != nil {
		fmt.Fprintf(stderr, "encrypt rule: %v\n", err)
		return exitcode.ConfigError
	}
	if len(finalRecipients) == 0 && selectedRule != nil {
		finalRecipients, err = cfg.ResolvedRecipients(*selectedRule)
		if err != nil {
			fmt.Fprintf(stderr, "encrypt rule recipients: %v\n", err)
			return exitcode.ConfigError
		}
	}
	if len(finalRecipients) == 0 {
		fmt.Fprintln(stderr, "encrypt: provide --recipient or --rule")
		return exitcode.UsageError
	}

	in, err := os.Open(*inPath)
	if err != nil {
		fmt.Fprintf(stderr, "open input: %v\n", err)
		return exitcode.ConfigError
	}
	defer in.Close()

	out, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintf(stderr, "create output: %v\n", err)
		return exitcode.ConfigError
	}
	defer out.Close()

	shouldArmor := false
	if selectedRule != nil {
		shouldArmor = cfg.Defaults.Armored
		if selectedRule.Armored != nil {
			shouldArmor = *selectedRule.Armored
		}
	}
	if armored.set {
		shouldArmor = armored.value
	}

	if err := crypto.Encrypt(in, out, crypto.EncryptOptions{
		Recipients: finalRecipients,
		Armored:    shouldArmor,
	}); err != nil {
		fmt.Fprintf(stderr, "encrypt %s: %v\n", *inPath, err)
		return exitcode.CryptoError
	}

	return exitcode.Success
}

func runDecrypt(_ context.Context, args []string, stdout, stderr io.Writer, global globalOptions) int {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", global.configPath, "policy file path")
	inPath := fs.String("in", "", "input file path")
	outPath := fs.String("out", "", "output file path")
	var identities csvListFlag
	fs.Var(&identities, "identity", "identity path list (repeatable or comma-separated)")
	if err := fs.Parse(args); err != nil {
		return exitcode.UsageError
	}
	if strings.TrimSpace(*inPath) == "" || strings.TrimSpace(*outPath) == "" {
		fmt.Fprintln(stderr, "decrypt: --in and --out are required")
		return exitcode.UsageError
	}
	finalIdentities := []string(identities)
	if len(finalIdentities) == 0 {
		cfg, err := loadPolicy(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "decrypt load policy: %v\n", err)
			return exitcode.ConfigError
		}
		finalIdentities = cfg.Identities
	}
	if len(finalIdentities) == 0 {
		fmt.Fprintln(stderr, "decrypt: no identities configured")
		return exitcode.ConfigError
	}

	in, err := os.Open(*inPath)
	if err != nil {
		fmt.Fprintf(stderr, "open input: %v\n", err)
		return exitcode.ConfigError
	}
	defer in.Close()

	out, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintf(stderr, "create output: %v\n", err)
		return exitcode.ConfigError
	}
	defer out.Close()

	if err := crypto.Decrypt(in, out, crypto.DecryptOptions{
		IdentityPaths: finalIdentities,
	}); err != nil {
		fmt.Fprintf(stderr, "decrypt %s: %v\n", *inPath, err)
		return exitcode.CryptoError
	}

	return exitcode.Success
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer, global globalOptions) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", global.configPath, "policy file path")
	if err := fs.Parse(args); err != nil {
		return exitcode.UsageError
	}

	repoPath, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "resolve working directory: %v\n", err)
		return exitcode.UnexpectedError
	}

	result, err := doctor.Run(ctx, doctor.Options{
		RepoPath:   repoPath,
		ConfigPath: *configPath,
	})
	if err != nil {
		if result != nil && len(result.Failures) > 0 {
			for _, failure := range result.Failures {
				fmt.Fprintf(stderr, "doctor failure: %s\n", failure)
			}
		}
		if result != nil && len(result.Warnings) > 0 {
			for _, warning := range result.Warnings {
				fmt.Fprintf(stdout, "doctor warning: %s\n", warning)
			}
		}
		switch {
		case errors.Is(err, doctor.ErrDoctorFailed):
			return exitcode.PolicyViolation
		case errors.Is(err, doctor.ErrGit):
			fmt.Fprintf(stderr, "doctor git: %v\n", err)
			return exitcode.GitError
		case errors.Is(err, doctor.ErrConfig):
			fmt.Fprintf(stderr, "doctor config: %v\n", err)
			return exitcode.ConfigError
		default:
			fmt.Fprintf(stderr, "doctor: %v\n", err)
			return exitcode.UnexpectedError
		}
	}

	for _, warning := range result.Warnings {
		fmt.Fprintf(stdout, "doctor warning: %s\n", warning)
	}
	fmt.Fprintln(stdout, "doctor: all checks passed")
	return exitcode.Success
}

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer, global globalOptions) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", global.configPath, "policy file path")
	if err := fs.Parse(args); err != nil {
		return exitcode.UsageError
	}

	repoPath, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "resolve working directory: %v\n", err)
		return exitcode.UnexpectedError
	}

	result, err := check.Run(ctx, check.Options{
		RepoPath:   repoPath,
		ConfigPath: *configPath,
	})
	if err != nil {
		if result != nil {
			for _, violation := range result.Violations {
				fmt.Fprintf(stderr, "policy violation: %s (%s)\n", violation.Path, violation.Reason)
			}
		}
		switch {
		case errors.Is(err, check.ErrCheckFailed):
			return exitcode.PolicyViolation
		case errors.Is(err, check.ErrConfig):
			fmt.Fprintf(stderr, "check config: %v\n", err)
			return exitcode.ConfigError
		case errors.Is(err, check.ErrGit):
			fmt.Fprintf(stderr, "check git: %v\n", err)
			return exitcode.GitError
		default:
			fmt.Fprintf(stderr, "check: %v\n", err)
			return exitcode.UnexpectedError
		}
	}

	fmt.Fprintf(stdout, "check: scanned %d protected file(s), no violations\n", result.ScannedFiles)
	return exitcode.Success
}

func loadPolicy(configPath string) (*policy.File, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	return policy.Parse(data)
}

func ensurePolicyTemplate(configPath string, force bool) error {
	if !force {
		if _, err := os.Stat(configPath); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	dir := filepath.Dir(configPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	return os.WriteFile(configPath, []byte(defaultPolicyTemplate), 0o644)
}

func resolveRuleForEncrypt(configPath, selector string) (*policy.Rule, *policy.File, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, nil, nil
	}

	cfg, err := loadPolicy(configPath)
	if err != nil {
		return nil, nil, err
	}

	for i := range cfg.Rules {
		if cfg.Rules[i].Path == selector {
			rule := cfg.Rules[i]
			return &rule, cfg, nil
		}
	}

	rule := cfg.Match(selector)
	if rule == nil {
		return nil, nil, fmt.Errorf("no rule matched selector %q", selector)
	}
	return rule, cfg, nil
}

type csvListFlag []string

func (f *csvListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *csvListFlag) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		*f = append(*f, trimmed)
	}
	return nil
}

type boolFlag struct {
	set   bool
	value bool
}

func (f *boolFlag) String() string {
	return strconv.FormatBool(f.value)
}

func (f *boolFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		value = "true"
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	f.value = parsed
	f.set = true
	return nil
}

func (f *boolFlag) IsBoolFlag() bool {
	return true
}

const defaultPolicyTemplate = `version: 1

defaults:
  armored: true
  max_file_size: 10485760
  on_missing_identity: fail

identities:
  - ~/.config/age/keys.txt

rules:
  - path: "secrets/*.env"
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]
    required: true
`
