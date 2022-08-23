// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	ed25519 "crypto/ed25519"

	mock "github.com/stretchr/testify/mock"
	toncore "github.com/tontechio/toncore-go"
)

// Fift is an autogenerated mock type for the Fift type
type Fift struct {
	mock.Mock
}

// HighloadWallet provides a mock function with given fields: privateKey, workchain, rawAddress, subwalletID, seqno, orders, bounceable, timeout, mode
func (_m *Fift) HighloadWallet(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, seqno uint32, orders []toncore.FiftHighloadOrder, bounceable bool, timeout int32, mode uint8) ([]byte, error) {
	ret := _m.Called(privateKey, workchain, rawAddress, subwalletID, seqno, orders, bounceable, timeout, mode)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, []byte, uint32, uint32, []toncore.FiftHighloadOrder, bool, int32, uint8) []byte); ok {
		r0 = rf(privateKey, workchain, rawAddress, subwalletID, seqno, orders, bounceable, timeout, mode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, []byte, uint32, uint32, []toncore.FiftHighloadOrder, bool, int32, uint8) error); ok {
		r1 = rf(privateKey, workchain, rawAddress, subwalletID, seqno, orders, bounceable, timeout, mode)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// HighloadWalletV2 provides a mock function with given fields: privateKey, workchain, rawAddress, subwalletID, orders, bounceable, timeout, mode
func (_m *Fift) HighloadWalletV2(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, orders []toncore.FiftHighloadOrder, bounceable bool, timeout int32, mode uint8) ([]byte, []byte, error) {
	ret := _m.Called(privateKey, workchain, rawAddress, subwalletID, orders, bounceable, timeout, mode)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, []byte, uint32, []toncore.FiftHighloadOrder, bool, int32, uint8) []byte); ok {
		r0 = rf(privateKey, workchain, rawAddress, subwalletID, orders, bounceable, timeout, mode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 []byte
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, []byte, uint32, []toncore.FiftHighloadOrder, bool, int32, uint8) []byte); ok {
		r1 = rf(privateKey, workchain, rawAddress, subwalletID, orders, bounceable, timeout, mode)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]byte)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(*ed25519.PrivateKey, int64, []byte, uint32, []toncore.FiftHighloadOrder, bool, int32, uint8) error); ok {
		r2 = rf(privateKey, workchain, rawAddress, subwalletID, orders, bounceable, timeout, mode)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// HighloadWalletV2One provides a mock function with given fields: privateKey, workchain, rawAddress, subwalletID, destination, amount, bounceable, timeout, bodyBoc, comment, mode
func (_m *Fift) HighloadWalletV2One(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, destination string, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, []byte, error) {
	ret := _m.Called(privateKey, workchain, rawAddress, subwalletID, destination, amount, bounceable, timeout, bodyBoc, comment, mode)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, []byte, uint32, string, string, bool, int32, []byte, string, uint8) []byte); ok {
		r0 = rf(privateKey, workchain, rawAddress, subwalletID, destination, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 []byte
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, []byte, uint32, string, string, bool, int32, []byte, string, uint8) []byte); ok {
		r1 = rf(privateKey, workchain, rawAddress, subwalletID, destination, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]byte)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(*ed25519.PrivateKey, int64, []byte, uint32, string, string, bool, int32, []byte, string, uint8) error); ok {
		r2 = rf(privateKey, workchain, rawAddress, subwalletID, destination, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// NewHighloadWallet provides a mock function with given fields: privateKey, workchainID, subwalletID
func (_m *Fift) NewHighloadWallet(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	ret := _m.Called(privateKey, workchainID, subwalletID)

	var r0 *toncore.FiftWallet
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, uint32) *toncore.FiftWallet); ok {
		r0 = rf(privateKey, workchainID, subwalletID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*toncore.FiftWallet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, uint32) error); ok {
		r1 = rf(privateKey, workchainID, subwalletID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewHighloadWalletV2 provides a mock function with given fields: privateKey, workchainID, subwalletID
func (_m *Fift) NewHighloadWalletV2(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	ret := _m.Called(privateKey, workchainID, subwalletID)

	var r0 *toncore.FiftWallet
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, uint32) *toncore.FiftWallet); ok {
		r0 = rf(privateKey, workchainID, subwalletID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*toncore.FiftWallet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, uint32) error); ok {
		r1 = rf(privateKey, workchainID, subwalletID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewWallet provides a mock function with given fields: privateKey, workchainID
func (_m *Fift) NewWallet(privateKey *ed25519.PrivateKey, workchainID int64) (*toncore.FiftWallet, error) {
	ret := _m.Called(privateKey, workchainID)

	var r0 *toncore.FiftWallet
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64) *toncore.FiftWallet); ok {
		r0 = rf(privateKey, workchainID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*toncore.FiftWallet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64) error); ok {
		r1 = rf(privateKey, workchainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewWalletV2 provides a mock function with given fields: privateKey, workchainID
func (_m *Fift) NewWalletV2(privateKey *ed25519.PrivateKey, workchainID int64) (*toncore.FiftWallet, error) {
	ret := _m.Called(privateKey, workchainID)

	var r0 *toncore.FiftWallet
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64) *toncore.FiftWallet); ok {
		r0 = rf(privateKey, workchainID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*toncore.FiftWallet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64) error); ok {
		r1 = rf(privateKey, workchainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewWalletV3 provides a mock function with given fields: privateKey, workchainID, subwalletID
func (_m *Fift) NewWalletV3(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	ret := _m.Called(privateKey, workchainID, subwalletID)

	var r0 *toncore.FiftWallet
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, uint32) *toncore.FiftWallet); ok {
		r0 = rf(privateKey, workchainID, subwalletID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*toncore.FiftWallet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, uint32) error); ok {
		r1 = rf(privateKey, workchainID, subwalletID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewWalletV4 provides a mock function with given fields: privateKey, workchainID, subwalletID
func (_m *Fift) NewWalletV4(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	ret := _m.Called(privateKey, workchainID, subwalletID)

	var r0 *toncore.FiftWallet
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, uint32) *toncore.FiftWallet); ok {
		r0 = rf(privateKey, workchainID, subwalletID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*toncore.FiftWallet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, uint32) error); ok {
		r1 = rf(privateKey, workchainID, subwalletID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RecoverStake provides a mock function with given fields:
func (_m *Fift) RecoverStake() ([]byte, error) {
	ret := _m.Called()

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidatorElectReq provides a mock function with given fields: walletAddress, electionDate, maxFactor, adnlAddress
func (_m *Fift) ValidatorElectReq(walletAddress string, electionDate uint64, maxFactor float64, adnlAddress string) ([]byte, error) {
	ret := _m.Called(walletAddress, electionDate, maxFactor, adnlAddress)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string, uint64, float64, string) []byte); ok {
		r0 = rf(walletAddress, electionDate, maxFactor, adnlAddress)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, uint64, float64, string) error); ok {
		r1 = rf(walletAddress, electionDate, maxFactor, adnlAddress)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidatorElectSigned provides a mock function with given fields: walletAddress, electionDate, maxFactor, adnlAddress, validatorPubKey, validatorSignature
func (_m *Fift) ValidatorElectSigned(walletAddress string, electionDate uint64, maxFactor float64, adnlAddress string, validatorPubKey []byte, validatorSignature []byte) ([]byte, error) {
	ret := _m.Called(walletAddress, electionDate, maxFactor, adnlAddress, validatorPubKey, validatorSignature)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string, uint64, float64, string, []byte, []byte) []byte); ok {
		r0 = rf(walletAddress, electionDate, maxFactor, adnlAddress, validatorPubKey, validatorSignature)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, uint64, float64, string, []byte, []byte) error); ok {
		r1 = rf(walletAddress, electionDate, maxFactor, adnlAddress, validatorPubKey, validatorSignature)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Wallet provides a mock function with given fields: privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, bodyBoc, comment, mode
func (_m *Fift) Wallet(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, seqno uint32, amount string, bounceable bool, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	ret := _m.Called(privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, bodyBoc, comment, mode)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, string, bool, []byte, string, uint8) []byte); ok {
		r0 = rf(privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, bodyBoc, comment, mode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, string, bool, []byte, string, uint8) error); ok {
		r1 = rf(privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, bodyBoc, comment, mode)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WalletV2 provides a mock function with given fields: privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, timeout, bodyBoc, comment, mode
func (_m *Fift) WalletV2(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	ret := _m.Called(privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, string, bool, int32, []byte, string, uint8) []byte); ok {
		r0 = rf(privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, string, bool, int32, []byte, string, uint8) error); ok {
		r1 = rf(privateKey, workchain, rawAddress, destination, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WalletV3 provides a mock function with given fields: privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode
func (_m *Fift) WalletV3(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, subwalletID uint32, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	ret := _m.Called(privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, uint32, string, bool, int32, []byte, string, uint8) []byte); ok {
		r0 = rf(privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, uint32, string, bool, int32, []byte, string, uint8) error); ok {
		r1 = rf(privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WalletV4 provides a mock function with given fields: privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode
func (_m *Fift) WalletV4(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, subwalletID uint32, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	ret := _m.Called(privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, uint32, string, bool, int32, []byte, string, uint8) []byte); ok {
		r0 = rf(privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ed25519.PrivateKey, int64, []byte, string, uint32, uint32, string, bool, int32, []byte, string, uint8) error); ok {
		r1 = rf(privateKey, workchain, rawAddress, destination, subwalletID, seqno, amount, bounceable, timeout, bodyBoc, comment, mode)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
