package executer

import (
	"github.com/tontechio/toncore-go/logger"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

func TestNewExecuter(t *testing.T) {
	type args struct {
		path    string
		args    []string
		timeout time.Duration
		logger  logr.Logger
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "new",
			args: args{
				path:    os.TempDir(),
				args:    nil,
				timeout: 10 * time.Second,
				logger:  logger.NewStdoutLogger(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewExecuter(tt.args.path, tt.args.args, tt.args.timeout, tt.args.logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewExecuter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("NewExecuter() got = %v", got)
			}
		})
	}
}
