package address

import (
	"testing"
)

func TestNew(t *testing.T) {
	type args struct {
		mnemonic string
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "new",
			args: args{
				mnemonic: "",
				password: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.mnemonic, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("New() got = %v", got)
			}
		})
	}
}
