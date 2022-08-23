package toncore

import (
	"context"
	"io"
	"os/exec"
)

//go:generate mockery -name=Executer -case snake

// Executer interface
type Executer interface {
	Exec(ctx context.Context, args []string, dir string) (io.Reader, error)
	ExecWithInput(ctx context.Context, args []string, dir string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error)
}

//go:generate mockery -name=WorkDir -case snake

// WorkDir interface
type WorkDir interface {
	Remove() error
	ReadFile(filename string) (result []byte, err error)
	WriteFile(filename string, data []byte) error
	Exec(args []string) (io.Reader, error)
}
