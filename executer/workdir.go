package executer

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/tontechio/toncore-go"
)

// WorkDir ...
type WorkDir struct {
	dir      string
	executer toncore.Executer
}

// Remove ...
func (wd *WorkDir) Remove() error {
	return os.RemoveAll(wd.dir)
}

// ReadFile ...
func (wd *WorkDir) ReadFile(filename string) (result []byte, err error) {
	fullPath := filepath.Join(wd.dir, filename)

	if result, err = ioutil.ReadFile(fullPath); err != nil {
		return nil, fmt.Errorf("ioutil.ReadFile() error with filename = %s: %w", fullPath, err)
	}

	return
}

// WriteFile ...
func (wd *WorkDir) WriteFile(filename string, data []byte) error {
	fullPath := filepath.Join(wd.dir, filename)

	if err := ioutil.WriteFile(fullPath, data, 0700); err != nil {
		return fmt.Errorf("ioutil.WriteFile() error with filename = %s: %w", fullPath, err)
	}

	return nil
}

// Exec ...
func (wd *WorkDir) Exec(args []string) (io.Reader, error) {
	// cmd
	reader, err := wd.executer.Exec(context.Background(), args, wd.dir)
	if err != nil {
		return nil, fmt.Errorf("executer.Exec() error: %w", err)
	}
	return reader, nil
}

// NewWorkDir ...
func NewWorkDir(executer toncore.Executer, dir string) (*WorkDir, error) {
	// create temp dir
	tmpDir, err := ioutil.TempDir(dir, "fift")
	if err != nil {
		return nil, fmt.Errorf("ioutil.TempDir error with dir = %v: %w", dir, err)
	}

	return &WorkDir{
		dir:      tmpDir,
		executer: executer,
	}, nil
}
