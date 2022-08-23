package toncore

import (
	"crypto/ed25519"

	"github.com/tontechio/toncore-go/address/hd"
)

// TonAddress struct
type TonAddress struct {
	Wallet               *hd.BIP44Params
	Workchain            uint8
	RawAddress           []byte
	MainnetBounceable    []byte
	MainnetNonBounceable []byte
	TestnetBounceable    []byte
	TestnetNonBounceable []byte
	PrivateKey           ed25519.PrivateKey
	PublicKey            ed25519.PublicKey
	ConstructorBoc       []byte
}

//go:generate mockery -name=HDAddress -case snake

// HDAddress interface
type HDAddress interface {
	Generate(addressIndex uint32) *TonAddress
	GeneratePrivateKey(addressIndex uint32) ed25519.PrivateKey
	GetBIP44Params(addressIndex uint32) *hd.BIP44Params
}
