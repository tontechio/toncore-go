package fift

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/tontechio/toncore-go"
	"github.com/tontechio/toncore-go/logger"
)

func getFift() (*Fift, error) {
	fift := os.Getenv("TONCORE_FIFT")
	fiftLib := os.Getenv("TONCORE_FIFT_LIB")
	fiftSmartcont := os.Getenv("TONCORE_FIFT_SMARTCONT")

	cmdArgs := []string{
		fift,
		fmt.Sprintf("-I%s:%s", fiftLib, fiftSmartcont),
	}

	fmt.Println(cmdArgs)

	f, err := NewFift(fift, cmdArgs, 10*time.Second, logger.NewStdoutLogger())
	if err != nil {
		return nil, fmt.Errorf("NewFift() error = %w", err)
	}

	return f, nil
}

func TestNewWallet(t *testing.T) {
	fift, err := getFift()
	if err != nil {
		t.Error(fmt.Errorf("can not create fift %w", err))
		return
	}

	key := []byte{129, 32, 69, 207, 68, 220, 131, 6, 109, 144, 177, 141, 208, 150, 145, 228, 69, 167, 203, 197, 242, 87, 10, 229, 157, 70, 59, 234, 160, 74, 231, 97}
	privateKey := ed25519.PrivateKey(key)

	result, err := fift.NewWallet(&privateKey, 0)
	if err != nil {
		t.Error(fmt.Errorf("fift.NewWallet() %w", err))
		return
	}

	assert.Equal(t, result.Workchain, int64(0))

	want := []byte{250, 227, 248, 86, 139, 111, 177, 184, 179, 104, 91, 219, 74, 143, 217, 129, 99, 184, 212, 176, 164, 148, 188, 104, 76, 9, 110, 99, 219, 148, 176, 160}
	get := result.RawAddress
	if !bytes.Equal(
		want,
		get,
	) {
		t.Errorf("fift.TestNewFift not equal result.RawAddress, want=%v, get=%v", want, get)
		return
	}

	want = []byte{129, 32, 69, 207, 68, 220, 131, 6, 109, 144, 177, 141, 208, 150, 145, 228, 69, 167, 203, 197, 242, 87, 10, 229, 157, 70, 59, 234, 160, 74, 231, 97}
	get = result.PrivateKey
	if !bytes.Equal(
		want,
		get,
	) {
		t.Errorf("fift.TestNewFift not equal result.PrivateKey, want=%v, get=%v", want, get)
		return
	}

	want = []byte{240, 54, 238, 230, 157, 249, 241, 211, 36, 160, 53, 51, 144, 103, 96, 125, 83, 208, 177, 192, 91, 214, 101, 32, 157, 145, 202, 134, 59, 233, 134, 199}
	get = result.PublicKey
	if !bytes.Equal(
		want,
		get,
	) {
		t.Errorf("fift.TestNewFift not equal result.PublicKey, want=%v, get=%v", want, get)
		return
	}

	want = []byte{181, 238, 156, 114, 65, 1, 3, 1, 0, 241, 0, 2, 207, 136, 1, 245, 199, 240, 173, 22, 223, 99, 113, 102, 208, 183, 182, 149, 31, 179, 2, 199, 113, 169, 97, 73, 41, 120, 208, 152, 18, 220, 199, 183, 41, 97, 64, 17, 145, 93, 31, 99, 112, 5, 199, 81, 75, 110, 123, 4, 130, 139, 108, 13, 172, 163, 170, 88, 133, 193, 217, 163, 1, 193, 190, 181, 195, 218, 88, 161, 32, 44, 247, 165, 126, 170, 102, 252, 22, 63, 90, 129, 82, 165, 2, 198, 115, 111, 162, 242, 105, 20, 80, 56, 150, 132, 138, 118, 117, 73, 13, 129, 224, 0, 0, 0, 16, 1, 2, 0, 186, 255, 0, 32, 221, 32, 130, 1, 76, 151, 186, 33, 130, 1, 51, 156, 186, 177, 156, 113, 176, 237, 68, 208, 211, 31, 215, 11, 255, 227, 4, 224, 164, 242, 96, 129, 2, 0, 215, 24, 32, 215, 11, 31, 237, 68, 208, 211, 31, 211, 255, 209, 81, 18, 186, 242, 161, 34, 249, 1, 84, 16, 68, 249, 16, 242, 162, 248, 0, 1, 211, 31, 49, 32, 215, 74, 150, 211, 7, 212, 2, 251, 0, 222, 209, 164, 200, 203, 31, 203, 255, 201, 237, 84, 0, 72, 0, 0, 0, 0, 240, 54, 238, 230, 157, 249, 241, 211, 36, 160, 53, 51, 144, 103, 96, 125, 83, 208, 177, 192, 91, 214, 101, 32, 157, 145, 202, 134, 59, 233, 134, 199, 239, 126, 158, 114}
	get = result.InitializationBoc
	if !bytes.Equal(
		want,
		get,
	) {
		t.Errorf("fift.TestNewFift not equal result.InitializationBoc, want=%v, get=%v", want, get)
		return
	}
}

func TestHightloadWalletV2(t *testing.T) {
	fift, err := getFift()
	if err != nil {
		t.Error(fmt.Errorf("can not create fift %w", err))
		return
	}

	privateKeyByte := []byte{129, 32, 69, 207, 68, 220, 131, 6, 109, 144, 177, 141, 208, 150, 145, 228, 69, 167, 203, 197, 242, 87, 10, 229, 157, 70, 59, 234, 160, 74, 231, 97}

	type args struct {
		privateKey  ed25519.PrivateKey // need new for every test
		address     []byte             // need new for every test
		workchain   int
		subwalletID uint32
		bounceable  bool
		orders      []toncore.FiftHighloadOrder
	}
	tests := []struct {
		name    string
		fift    *Fift
		args    args
		wantErr bool
	}{
		{
			name: "1",
			fift: fift,
			args: args{
				workchain:   0,
				privateKey:  ed25519.PrivateKey(privateKeyByte),
				address:     []byte{250, 227, 248, 86, 139, 111, 177, 184, 179, 104, 91, 219, 74, 143, 217, 129, 99, 184, 212, 176, 164, 148, 188, 104, 76, 9, 110, 99, 219, 148, 176, 160},
				bounceable:  true,
				subwalletID: 1,
				orders: []toncore.FiftHighloadOrder{
					{"EQCs0H7UKRoOYdbrsVyl5gqDzMRxRzfLDNIhUoaCwNm_hukj", "1", ""},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, get, err := tt.fift.HighloadWalletV2(&tt.args.privateKey, 0, tt.args.address, tt.args.subwalletID, tt.args.orders, tt.args.bounceable, toncore.FiftWalletTimeoutDefault, toncore.FiftWalletModeDefault)
			assert.NoError(t, err)

			if !tt.wantErr {
				assert.Nil(t, err)
				assert.NotNil(t, id)
				assert.NotNil(t, get)
			}
		})
	}
}

func TestFift_HighloadWalletV2One(t *testing.T) {
	fift, err := getFift()
	if err != nil {
		t.Error(fmt.Errorf("can not create fift %w", err))
		return
	}

	privateKeyByte := []byte{129, 32, 69, 207, 68, 220, 131, 6, 109, 144, 177, 141, 208, 150, 145, 228, 69, 167, 203, 197, 242, 87, 10, 229, 157, 70, 59, 234, 160, 74, 231, 97}
	privateKey := ed25519.PrivateKey(privateKeyByte)

	type args struct {
		privateKey  *ed25519.PrivateKey
		workchain   int64
		rawAddress  []byte
		subwalletID uint32
		destination string
		amount      string
		bounceable  bool
		timeout     int32
		bodyBoc     []byte
		comment     string
		mode        uint8
	}
	tests := []struct {
		name    string
		fift    *Fift
		args    args
		wantErr bool
	}{
		{
			name: "1",
			fift: fift,
			args: args{
				workchain:   0,
				privateKey:  &privateKey,
				rawAddress:  []byte{250, 227, 248, 86, 139, 111, 177, 184, 179, 104, 91, 219, 74, 143, 217, 129, 99, 184, 212, 176, 164, 148, 188, 104, 76, 9, 110, 99, 219, 148, 176, 160},
				bounceable:  true,
				subwalletID: 1,
				destination: "EQCs0H7UKRoOYdbrsVyl5gqDzMRxRzfLDNIhUoaCwNm_hukj",
				amount:      "1",
				timeout:     60,
				bodyBoc:     nil,
				comment:     "comment",
				mode:        3,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, get, err := tt.fift.HighloadWalletV2One(tt.args.privateKey, tt.args.workchain, tt.args.rawAddress, tt.args.subwalletID, tt.args.destination, tt.args.amount, tt.args.bounceable, tt.args.timeout, tt.args.bodyBoc, tt.args.comment, tt.args.mode)
			if !tt.wantErr {
				assert.Nil(t, err)
				assert.NotNil(t, id)
				assert.NotNil(t, get)
			}
		})
	}
}

func TestWallet(t *testing.T) {
	fift, err := getFift()
	if err != nil {
		t.Error(fmt.Errorf("can not create fift %w", err))
		return
	}

	privateKeyByte := []byte{129, 32, 69, 207, 68, 220, 131, 6, 109, 144, 177, 141, 208, 150, 145, 228, 69, 167, 203, 197, 242, 87, 10, 229, 157, 70, 59, 234, 160, 74, 231, 97}

	type args struct {
		privateKey  ed25519.PrivateKey // need new for every test
		address     []byte             // need new for every test
		workchain   int
		bounceable  bool
		nonce       uint32
		destination string
		amount      string
		comment     string
		bodyBoc     []byte
	}
	tests := []struct {
		name string
		fift *Fift
		args args
		want []byte
	}{
		{
			name: "1",
			fift: fift,
			args: args{
				workchain:   0,
				privateKey:  ed25519.PrivateKey(privateKeyByte),
				address:     []byte{250, 227, 248, 86, 139, 111, 177, 184, 179, 104, 91, 219, 74, 143, 217, 129, 99, 184, 212, 176, 164, 148, 188, 104, 76, 9, 110, 99, 219, 148, 176, 160},
				bounceable:  true,
				nonce:       0,
				destination: "EQCs0H7UKRoOYdbrsVyl5gqDzMRxRzfLDNIhUoaCwNm_hukj",
				amount:      "1",
				comment:     "",
				bodyBoc:     nil,
			},
			want: []byte{181, 238, 156, 114, 65, 1, 2, 1, 0, 161, 0, 1, 207, 136, 1, 245, 199, 240, 173, 22, 223, 99, 113, 102, 208, 183, 182, 149, 31, 179, 2, 199, 113, 169, 97, 73, 41, 120, 208, 152, 18, 220, 199, 183, 41, 97, 64, 1, 106, 145, 239, 61, 122, 111, 160, 78, 114, 88, 239, 9, 41, 87, 198, 218, 7, 85, 101, 252, 58, 105, 81, 22, 185, 159, 246, 67, 81, 129, 156, 241, 175, 85, 45, 41, 26, 196, 198, 172, 10, 153, 154, 125, 108, 128, 41, 58, 212, 243, 254, 107, 115, 28, 169, 193, 41, 230, 59, 111, 190, 17, 160, 56, 0, 0, 0, 0, 28, 1, 0, 104, 98, 0, 86, 104, 63, 106, 20, 141, 7, 48, 235, 117, 216, 174, 82, 243, 5, 65, 230, 98, 56, 163, 155, 229, 134, 105, 16, 169, 67, 65, 96, 108, 223, 195, 33, 220, 214, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 163, 161, 66, 162},
		},
		{
			name: "2",
			fift: fift,
			args: args{
				privateKey:  ed25519.PrivateKey(privateKeyByte),
				address:     []byte{250, 227, 248, 86, 139, 111, 177, 184, 179, 104, 91, 219, 74, 143, 217, 129, 99, 184, 212, 176, 164, 148, 188, 104, 76, 9, 110, 99, 219, 148, 176, 160},
				workchain:   0,
				bounceable:  true,
				nonce:       0,
				destination: "EQCs0H7UKRoOYdbrsVyl5gqDzMRxRzfLDNIhUoaCwNm_hukj",
				amount:      "1",
				comment:     "",
				bodyBoc:     nil,
			},
			want: []byte{181, 238, 156, 114, 65, 1, 2, 1, 0, 161, 0, 1, 207, 136, 1, 245, 199, 240, 173, 22, 223, 99, 113, 102, 208, 183, 182, 149, 31, 179, 2, 199, 113, 169, 97, 73, 41, 120, 208, 152, 18, 220, 199, 183, 41, 97, 64, 1, 106, 145, 239, 61, 122, 111, 160, 78, 114, 88, 239, 9, 41, 87, 198, 218, 7, 85, 101, 252, 58, 105, 81, 22, 185, 159, 246, 67, 81, 129, 156, 241, 175, 85, 45, 41, 26, 196, 198, 172, 10, 153, 154, 125, 108, 128, 41, 58, 212, 243, 254, 107, 115, 28, 169, 193, 41, 230, 59, 111, 190, 17, 160, 56, 0, 0, 0, 0, 28, 1, 0, 104, 98, 0, 86, 104, 63, 106, 20, 141, 7, 48, 235, 117, 216, 174, 82, 243, 5, 65, 230, 98, 56, 163, 155, 229, 134, 105, 16, 169, 67, 65, 96, 108, 223, 195, 33, 220, 214, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 163, 161, 66, 162},
		},
		{
			name: "3",
			fift: fift,
			args: args{
				privateKey:  ed25519.PrivateKey(privateKeyByte),
				address:     []byte{250, 227, 248, 86, 139, 111, 177, 184, 179, 104, 91, 219, 74, 143, 217, 129, 99, 184, 212, 176, 164, 148, 188, 104, 76, 9, 110, 99, 219, 148, 176, 160},
				workchain:   0,
				bounceable:  false,
				nonce:       0,
				destination: "EQCs0H7UKRoOYdbrsVyl5gqDzMRxRzfLDNIhUoaCwNm_hukj",
				amount:      "1",
				comment:     "test",
				bodyBoc:     nil,
			},
			want: []byte{181, 238, 156, 114, 65, 1, 2, 1, 0, 169, 0, 1, 207, 136, 1, 245, 199, 240, 173, 22, 223, 99, 113, 102, 208, 183, 182, 149, 31, 179, 2, 199, 113, 169, 97, 73, 41, 120, 208, 152, 18, 220, 199, 183, 41, 97, 64, 5, 123, 12, 180, 180, 127, 89, 59, 133, 110, 245, 130, 242, 111, 69, 200, 162, 188, 115, 226, 166, 229, 18, 35, 20, 43, 179, 59, 91, 62, 148, 158, 127, 194, 39, 2, 220, 61, 3, 51, 221, 215, 213, 207, 29, 200, 89, 53, 56, 86, 84, 116, 70, 163, 64, 204, 80, 41, 52, 137, 158, 6, 228, 240, 32, 0, 0, 0, 0, 28, 1, 0, 120, 66, 0, 86, 104, 63, 106, 20, 141, 7, 48, 235, 117, 216, 174, 82, 243, 5, 65, 230, 98, 56, 163, 155, 229, 134, 105, 16, 169, 67, 65, 96, 108, 223, 195, 33, 220, 214, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 116, 101, 115, 116, 76, 201, 150, 105},
		},
		{
			name: "4",
			fift: fift,
			args: args{
				privateKey:  ed25519.PrivateKey(privateKeyByte),
				address:     []byte{250, 227, 248, 86, 139, 111, 177, 184, 179, 104, 91, 219, 74, 143, 217, 129, 99, 184, 212, 176, 164, 148, 188, 104, 76, 9, 110, 99, 219, 148, 176, 160},
				workchain:   1,
				bounceable:  false,
				nonce:       0,
				destination: "EQCs0H7UKRoOYdbrsVyl5gqDzMRxRzfLDNIhUoaCwNm_hukj",
				amount:      "1",
				comment:     "",
				bodyBoc:     nil,
			},
			want: []byte{181, 238, 156, 114, 65, 1, 2, 1, 0, 161, 0, 1, 207, 136, 1, 245, 199, 240, 173, 22, 223, 99, 113, 102, 208, 183, 182, 149, 31, 179, 2, 199, 113, 169, 97, 73, 41, 120, 208, 152, 18, 220, 199, 183, 41, 97, 64, 2, 246, 192, 76, 181, 23, 162, 163, 39, 205, 28, 232, 129, 128, 127, 244, 40, 252, 100, 248, 217, 36, 60, 64, 250, 84, 61, 134, 201, 16, 64, 187, 114, 51, 139, 188, 28, 100, 72, 55, 214, 49, 103, 64, 246, 135, 174, 147, 168, 86, 69, 57, 71, 71, 29, 35, 203, 245, 129, 251, 73, 170, 17, 24, 112, 0, 0, 0, 0, 28, 1, 0, 104, 66, 0, 86, 104, 63, 106, 20, 141, 7, 48, 235, 117, 216, 174, 82, 243, 5, 65, 230, 98, 56, 163, 155, 229, 134, 105, 16, 169, 67, 65, 96, 108, 223, 195, 33, 220, 214, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 226, 203, 201, 223},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			get, err := tt.fift.Wallet(&tt.args.privateKey, 0, tt.args.address, tt.args.destination, tt.args.nonce, tt.args.amount, tt.args.bounceable, tt.args.bodyBoc, tt.args.comment, toncore.FiftWalletModeDefault)
			assert.NoError(t, err)

			if !bytes.Equal(
				tt.want,
				get,
			) {
				t.Errorf("fift.Transfer args=%v, want=%v, get=%v", tt.args, tt.want, get)
				return
			}
		})
	}
}

func TestValidatorElectReq(t *testing.T) {
	fift, err := getFift()
	if err != nil {
		t.Error(fmt.Errorf("can not create fift %w", err))
		return
	}

	type args struct {
		walletAddress string
		electionDate  uint64
		maxFactor     float64
		adnlAddress   string
	}
	tests := []struct {
		name string
		fift *Fift
		args args
		want []byte
	}{
		{
			name: "1",
			fift: fift,
			args: args{
				walletAddress: "-1:798e70f6dd9d00a679169d274d1597bd65cb59776fabbe2d067c1c7b9d6b9fae",
				electionDate:  1585039917,
				maxFactor:     1,
				adnlAddress:   "798e70f6dd9d00a679169d274d1597bd65cb59776fabbe2d067c1c7b9d6b9fae",
			},
			want: []byte{101, 76, 80, 116, 94, 121, 202, 45, 0, 1, 0, 0, 121, 142, 112, 246, 221, 157, 0, 166, 121, 22, 157, 39, 77, 21, 151, 189, 101, 203, 89, 119, 111, 171, 190, 45, 6, 124, 28, 123, 157, 107, 159, 174, 121, 142, 112, 246, 221, 157, 0, 166, 121, 22, 157, 39, 77, 21, 151, 189, 101, 203, 89, 119, 111, 171, 190, 45, 6, 124, 28, 123, 157, 107, 159, 174},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			get, err := tt.fift.ValidatorElectReq(tt.args.walletAddress, tt.args.electionDate, tt.args.maxFactor, tt.args.adnlAddress)
			assert.NoError(t, err)

			if !bytes.Equal(
				tt.want,
				get,
			) {
				t.Errorf("fift.Transfer args=%v, want=%v, get=%v", tt.args, tt.want, get)
				return
			}
		})
	}
}
