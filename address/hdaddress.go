package address

import (
	"crypto/ed25519"

	"github.com/cosmos/go-bip39"

	"github.com/tontechio/toncore-go"
	"github.com/tontechio/toncore-go/address/hd"
)

// BIP44 default params
const (
	bip44Purpose  = 44
	bip44CoinType = 396
	bip44Account  = 0
	bip44Change   = false
)

// HDAddress struct
type HDAddress struct {
	secret    [32]byte
	chainCode [32]byte
}

// Generate ...
func (t *HDAddress) Generate(addressIndex uint32) *toncore.TonAddress {
	addr := toncore.TonAddress{
		Workchain: 0x00,
		Wallet:    t.GetBIP44Params(addressIndex),
	}

	privateKey := t.GeneratePrivateKey(addressIndex)
	addr.PrivateKey = privateKey.Seed()
	addr.PublicKey = privateKey.Public().(ed25519.PublicKey)

	return &addr
}

// GeneratePrivateKey ...
func (t *HDAddress) GeneratePrivateKey(addressIndex uint32) ed25519.PrivateKey {
	hdParams := t.GetBIP44Params(addressIndex)
	seed, _ := hd.DerivePrivateKeyForPath(t.secret, t.chainCode, hdParams.String())
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey
}

// GetBIP44Params m/44'/396'/0'/0'/N'
func (t *HDAddress) GetBIP44Params(addressIndex uint32) *hd.BIP44Params {
	hdParams := hd.BIP44Params{
		Purpose:      bip44Purpose,
		CoinType:     bip44CoinType,
		Account:      bip44Account,
		Change:       bip44Change,
		AddressIndex: addressIndex,
	}
	return &hdParams
}

// New returns new TON instance
func New(mnemonic, password string) (*HDAddress, error) {
	ton := HDAddress{}
	seed := bip39.NewSeed(mnemonic, password)
	ton.secret, ton.chainCode = hd.ComputeMastersFromSeed(seed)
	return &ton, nil
}
