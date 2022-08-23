package toncore

import "crypto/ed25519"

//go:generate mockery --name=Mnemonic --case snake

// Mnemonic ...
type Mnemonic interface {
	String()
	PrivateKey() ed25519.PrivateKey
	PublicKey() ed25519.PublicKey
	PublicKeySigned() []byte
	Mnemonic() []string
}
