package toncore

import "crypto/ed25519"

// Wallet versions
const (
	HighloadWallet   = "highload-wallet"
	HighloadWalletV2 = "highload-wallet-v2"
	Wallet           = "wallet"
	WalletV2         = "wallet-v2"
	WalletV3         = "wallet-v3"
	WalletV4         = "wallet-v4"
)

// FiftWallet ...
type FiftWallet struct {
	Version           string
	Workchain         int64
	RawAddress        []byte
	PrivateKey        []byte
	PublicKey         []byte
	InitializationBoc []byte
	SubwalletID       *uint32
}

const (
	FiftWalletTimeoutDefault = 60
	FiftWalletModeDefault    = 3
)

type FiftHighloadOrder struct {
	Destination string
	Amount      string
	Comment     string
}

//go:generate mockery --name=Fift --case snake

// Fift ...
type Fift interface {
	NewHighloadWallet(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*FiftWallet, error)
	NewHighloadWalletV2(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*FiftWallet, error)
	NewWallet(privateKey *ed25519.PrivateKey, workchainID int64) (*FiftWallet, error)
	NewWalletV2(privateKey *ed25519.PrivateKey, workchainID int64) (*FiftWallet, error)
	NewWalletV3(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*FiftWallet, error)
	NewWalletV4(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*FiftWallet, error)
	RecoverStake() (boc []byte, err error)
	ValidatorElectReq(walletAddress string, electionDate uint64, maxFactor float64, adnlAddress string) (bin []byte, err error)
	ValidatorElectSigned(walletAddress string, electionDate uint64, maxFactor float64, adnlAddress string, validatorPubKey, validatorSignature []byte) (boc []byte, err error)
	HighloadWallet(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, seqno uint32, orders []FiftHighloadOrder, bounceable bool, timeout int32, mode uint8) (boc []byte, err error)
	HighloadWalletV2(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, orders []FiftHighloadOrder, bounceable bool, timeout int32, mode uint8) (queryID []byte, boc []byte, err error)
	HighloadWalletV2One(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, destination string, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, []byte, error)
	Wallet(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, seqno uint32, amount string, bounceable bool, bodyBoc []byte, comment string, mode uint8) (boc []byte, err error)
	WalletV2(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) (boc []byte, err error)
	WalletV3(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, subwalletID uint32, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) (boc []byte, err error)
	WalletV4(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, subwalletID uint32, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) (boc []byte, err error)
}
