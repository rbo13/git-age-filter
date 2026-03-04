package git

import "errors"

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
