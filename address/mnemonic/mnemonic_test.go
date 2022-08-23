package mnemonic

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
)

func TestMnemomic_PublicKeySigned(t *testing.T) {
	type fields struct {
		mnemonic []string
		password string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "test 1",
			fields: fields{
				// album liar eternal pause reduce bomb clown expect ticket chunk trumpet silent reform swap nature suspect fetch business spread tree tired example tray width
				mnemonic: []string{
					"album",
					"liar",
					"eternal",
					"pause",
					"reduce",
					"bomb",
					"clown",
					"expect",
					"ticket",
					"chunk",
					"trumpet",
					"silent",
					"reform",
					"swap",
					"nature",
					"suspect",
					"fetch",
					"business",
					"spread",
					"tree",
					"tired",
					"example",
					"tray",
					"width",
				},
				password: "",
			},
			want: "PuZbCqNeHCf1e-YeSMkis8ohF5HYIHJRiE80ddQM_QQpHbAx",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMnemonic(tt.fields.mnemonic, tt.fields.password)
			if err != nil {
				t.Errorf("NewMnemonic() error = %v", err)
				return
			}

			got := m.PublicKeySigned()
			encoded := base64.URLEncoding.EncodeToString(got)
			if !reflect.DeepEqual(encoded, tt.want) {
				t.Errorf("PublicKeySigned() got = %v, want %v", encoded, tt.want)
			}
		})
	}
}

func TestGenerateMnemonic(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:    "empty password",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateMnemonic(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println(got.mnemonic)
		})
	}
}
