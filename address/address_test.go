package address

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/tontechio/toncore-go/address/crc"
)

func Test_GetCRC16(t *testing.T) {
	pubkey, _ := hex.DecodeString(`3ee65b0aa35e1c27f57be61e48c922b3ca211791d8207251884f3475d40cfd04291d`)

	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "pubkey",
			args: args{data: pubkey},
			want: []byte{0xb0, 0x31},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crc.GetCRC16(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCRC16() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestNewAddressFromFriendly(t *testing.T) {
	addressFriendly := "kf9c4zzQzEGsHx09xGxbu4JosGKHFeJOvkKfR49hiS318SWV"
	addressHex, _ := hex.DecodeString("5ce33cd0cc41ac1f1d3dc46c5bbb8268b0628715e24ebe429f478f61892df5f1")
	type args struct {
		address string
	}
	tests := []struct {
		name    string
		args    args
		want    Address
		wantErr bool
	}{
		{
			name: "test",
			args: args{
				address: addressFriendly,
			},
			want: Address{
				Workchain: -1,
				Raw:       addressHex,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAddressFromFriendly(tt.args.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAddressFromFriendly() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAddressFromFriendly() got = %v, want %v", got, tt.want)
			}
		})
	}
}
