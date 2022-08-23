package executer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/go-logr/logr"
)

type executer struct {
	path    string
	args    []string
	timeout time.Duration
	logger  logr.Logger
}

// Exec implementation
func (e *executer) Exec(ctx context.Context, args []string, dir string) (io.Reader, error) {
	var (
		stdOut = new(bytes.Buffer)
		stdErr = new(bytes.Buffer)
		stdIn  = new(bytes.Buffer)
	)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	execCmd := exec.CommandContext(ctx, "")
	execCmd.Dir = dir
	execCmd.Path = e.path
	execCmd.Args = append(e.args, args...)
	execCmd.Stdout = stdOut
	execCmd.Stderr = stdErr
	execCmd.Stdin = stdIn

	e.logger.Info("exec", "dir", dir, "cmd", execCmd.String())

	if err := execCmd.Run(); err != nil {
		return nil, fmt.Errorf("execCmd.Start() error with err = %v: %w", stdErr.String(), err)
	}

	if len(stdErr.String()) > 0 {
		return nil, fmt.Errorf("execCmd.Start() error: %v", stdErr.String())
	}

	return stdOut, nil
}

// ExecWithInput implementation
func (e *executer) ExecWithInput(ctx context.Context, args []string, dir string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	var (
		stdErr = new(bytes.Buffer)
	)

	execCmd := exec.CommandContext(ctx, "")
	execCmd.Dir = dir
	execCmd.Path = e.path
	execCmd.Args = append(e.args, args...)
	execCmd.Stderr = stdErr

	stdIn, err := execCmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("execCmd.StdinPipe() error: %w", err)
	}

	stdOut, err := execCmd.StdoutPipe()
	if err != nil {
		if err := stdIn.Close(); err != nil {
			e.logger.Error(err, "close failed")
		}
		return nil, nil, nil, fmt.Errorf("execCmd.StdoutPipe() error: %w", err)
	}

	e.logger.Info("execWithInput", "dir", dir, "cmd", execCmd.String())

	if err := execCmd.Start(); err != nil {
		if err := stdIn.Close(); err != nil {
			e.logger.Error(err, "close failed")
		}
		if err := stdOut.Close(); err != nil {
			e.logger.Error(err, "close failed")
		}
		return nil, nil, nil, fmt.Errorf("execCmd.Start() error with err = %v: %w", stdErr.String(), err)
	}

	return execCmd, stdIn, stdOut, nil
}

// NewExecuter instance
func NewExecuter(path string, args []string, timeout time.Duration, logger logr.Logger) (*executer, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}

	var p = executer{
		path:    path,
		args:    args,
		timeout: timeout,
		logger:  logger,
	}

	return &p, nil
}
