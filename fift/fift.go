package fift

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/tontechio/toncore-go"
	"github.com/tontechio/toncore-go/address"
	"github.com/tontechio/toncore-go/executer"
)

// Fift ...
type Fift struct {
	executer toncore.Executer
	logger   logr.Logger
}

func (f *Fift) getDir() string {
	return os.TempDir()
}

func (f *Fift) newWallet(version string, args []string, privateKey *ed25519.PrivateKey, subwalletID *uint32, name string) (*toncore.FiftWallet, error) {
	w := toncore.FiftWallet{
		Version:     version,
		PrivateKey:  privateKey.Seed(),
		SubwalletID: subwalletID,
	}

	fd, err := executer.NewWorkDir(f.executer, f.getDir())
	if err != nil {
		return nil, fmt.Errorf("executer.NewWorkDir() error %w", err)
	}
	defer func() {
		if err := fd.Remove(); err != nil {
			f.logger.Error(err, "remove workdir")
		}
	}()

	filename := name + ".pk"
	err = fd.WriteFile(filename, w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("fd.WriteFile() error with filename = %s: %w", filename, err)
	}

	_, err = fd.Exec(args)
	if err != nil {
		return nil, fmt.Errorf("fd.Exec() error: %w", err)
	}

	// read address, boc
	if subwalletID != nil && (version == toncore.HighloadWallet || version == toncore.HighloadWalletV2) {
		name = name + strconv.FormatUint(uint64(*subwalletID), 10)
	}
	filename = name + ".addr"

	rawAddress, err := fd.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("fd.ReadFile() error with filename = %s: %w", filename, err)
	}

	addr, err := address.NewAddressFromFullRaw(rawAddress)
	if err != nil {
		return nil, fmt.Errorf("ton.NewAddressFromFullRaw() error: %w", err)
	}
	w.Workchain = addr.Workchain
	w.RawAddress = addr.Raw

	filename = name + "-query.boc"
	if w.InitializationBoc, err = fd.ReadFile(filename); err != nil {
		return nil, fmt.Errorf("fd.ReadFile() error with filename = %s: %w", filename, err)
	}

	w.PublicKey = ed25519.NewKeyFromSeed(w.PrivateKey).Public().(ed25519.PublicKey)

	return &w, nil
}

// NewHighloadWallet ...
func (f *Fift) NewHighloadWallet(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	// command: fift -s new-highload-wallet.fif <workchain-id> <subwallet-id> [<filename-base>]
	args := []string{"-s", "new-highload-wallet.fif", strconv.FormatInt(workchainID, 10), strconv.FormatUint(uint64(subwalletID), 10), "wallet"}
	return f.newWallet("highload-wallet", args, privateKey, &subwalletID, "wallet")
}

// NewHighloadWalletV2 ...
func (f *Fift) NewHighloadWalletV2(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	// command: fift -s new-highload-wallet-v2.fif <workchain-id> <subwallet-id> [<filename-base>]
	args := []string{"-s", "new-highload-wallet-v2.fif", strconv.FormatInt(workchainID, 10), strconv.FormatUint(uint64(subwalletID), 10), "wallet"}
	return f.newWallet("highload-wallet-v2", args, privateKey, &subwalletID, "wallet")
}

// NewWallet ...
func (f *Fift) NewWallet(privateKey *ed25519.PrivateKey, workchainID int64) (*toncore.FiftWallet, error) {
	// command: fift -s new-wallet.fif <workchain-id> [<filename-base>]
	args := []string{"-s", "new-wallet.fif", fmt.Sprintf("%d", workchainID), "wallet"}
	return f.newWallet("wallet", args, privateKey, nil, "wallet")
}

// NewWalletV2 ...
func (f *Fift) NewWalletV2(privateKey *ed25519.PrivateKey, workchainID int64) (*toncore.FiftWallet, error) {
	// command: fift -s new-wallet-v2.fif <workchain-id> [<filename-base>]
	args := []string{"-s", "new-wallet-v2.fif", strconv.FormatInt(workchainID, 10), "wallet"}
	return f.newWallet("wallet-v2", args, privateKey, nil, "wallet")
}

// NewWalletV3 ...
func (f *Fift) NewWalletV3(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	// command: fift -s new-wallet-v3.fif <workchain-id> <wallet-id> [<filename-base>]
	args := []string{"-s", "new-wallet-v3.fif", strconv.FormatInt(workchainID, 10), strconv.FormatUint(uint64(subwalletID), 10), "wallet"}
	return f.newWallet("wallet-v3", args, privateKey, &subwalletID, "wallet")
}

// NewWalletV4 ...
func (f *Fift) NewWalletV4(privateKey *ed25519.PrivateKey, workchainID int64, subwalletID uint32) (*toncore.FiftWallet, error) {
	// command: fift -s new-wallet-v4.fif <workchain-id> <wallet-id> [<filename-base>]
	args := []string{"-s", "new-wallet-v4.fif", strconv.FormatInt(workchainID, 10), strconv.FormatUint(uint64(subwalletID), 10), "wallet"}
	return f.newWallet("wallet-v4", args, privateKey, &subwalletID, "wallet")
}

func (f *Fift) wallet(args []string, privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID *uint32, bodyBoc []byte, orders []toncore.FiftHighloadOrder, name string) (io.Reader, []byte, error) {
	// prepare temp dir
	fd, err := executer.NewWorkDir(f.executer, f.getDir())
	if err != nil {
		return nil, nil, fmt.Errorf("executer.NewWorkDir() error %w", err)
	}
	defer func() {
		if err := fd.Remove(); err != nil {
			f.logger.Error(err, "remove workdir")
		}
	}()

	// write pk
	filename := name + ".pk"
	if err := fd.WriteFile(filename, privateKey.Seed()); err != nil {
		return nil, nil, fmt.Errorf("fd.WriteFile() error with filename = %s: %w", filename, err)
	}

	// write addr
	addr := address.Address{
		Workchain: workchain,
		Raw:       rawAddress,
	}
	if subwalletID != nil {
		filename = name + strconv.FormatUint(uint64(*subwalletID), 10) + ".addr"
	} else {
		filename = name + ".addr"
	}
	if err := fd.WriteFile(filename, addr.GetFullRawAddress()); err != nil {
		return nil, nil, fmt.Errorf("fd.WriteFile() error with filename = %s: %w", filename, err)
	}

	// write body
	if bodyBoc != nil {
		if err := fd.WriteFile("body.boc", bodyBoc); err != nil {
			return nil, nil, fmt.Errorf("fd.WriteFile() error with filename = %s: %w", "body.boc", err)
		}
	}

	// write orders
	if orders != nil {
		filename = name + "-orders.txt"
		byteOrders := []byte{}
		for _, order := range orders {
			byteOrders = append(byteOrders, []byte(fmt.Sprintf("SEND %s %s %s\n", order.Destination, order.Amount, order.Comment))...)
		}
		if err := fd.WriteFile(filename, byteOrders); err != nil {
			return nil, nil, fmt.Errorf("fd.WriteFile() error with filename = %s: %w", filename, err)
		}
	}

	// run
	reader, err := fd.Exec(args)
	if err != nil {
		return reader, nil, fmt.Errorf("fd.Exec() error: %w", err)
	}

	// read boc
	var boc []byte
	filename = name + "-query.boc"
	if boc, err = fd.ReadFile(filename); err != nil {
		return reader, nil, fmt.Errorf("fd.ReadFile() error with filename = %s: %w", filename, err)
	}

	return reader, boc, nil
}

// HighloadWallet ...
func (f *Fift) HighloadWallet(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, seqno uint32, orders []toncore.FiftHighloadOrder, bounceable bool, timeout int32, mode uint8) ([]byte, error) {
	if len(orders) <= 0 || len(orders) > 254 {
		return nil, fmt.Errorf("orders size must be 1..254")
	}

	// command: fift -s highload-wallet.fif <filename-base> <subwallet-id> <seqno> <order-file> [-n|-b] [-t<timeout>] [<savefile>]
	args := []string{"-s", "highload-wallet.fif", "wallet", strconv.FormatUint(uint64(subwalletID), 10), strconv.FormatUint(uint64(seqno), 10), "wallet-orders.txt"}

	if bounceable {
		args = append(args, []string{"-b"}...)
	} else {
		args = append(args, []string{"-n"}...)
	}

	args = append(args, []string{"-t", strconv.FormatUint(uint64(timeout), 10)}...)
	args = append(args, []string{"-m", strconv.FormatUint(uint64(mode), 10)}...)

	_, boc, err := f.wallet(args, privateKey, workchain, rawAddress, &subwalletID, nil, orders, "wallet")
	return boc, err
}

func (f *Fift) readQueryID(reader io.Reader) ([]byte, error) {
	bufReader := bufio.NewReader(reader)
	for {
		line, _, err := bufReader.ReadLine()
		if err == io.EOF {
			break
		}
		// "Query_id is 7039839131962436930 = 0x61B288645083ED42 "
		if bytes.Equal(line[0:8], []byte("Query_id")) {
			l := strings.Split(string(line), " ")
			queryID, err := hex.DecodeString(l[4][2:])
			if err != nil {
				return nil, fmt.Errorf("bad query id in '%s'", line)
			}
			return queryID, nil
		}
	}
	return nil, fmt.Errorf("query id not found")
}

// HighloadWalletV2 ...
func (f *Fift) HighloadWalletV2(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, orders []toncore.FiftHighloadOrder, bounceable bool, timeout int32, mode uint8) ([]byte, []byte, error) {
	if len(orders) <= 0 || len(orders) > 254 {
		return nil, nil, fmt.Errorf("orders size must be 1..254")
	}

	// command: fift -s highload-wallet-v2.fif <filename-base> <subwallet-id> <order-file> [-n|-b] [-t<timeout>] [<savefile>]
	args := []string{"-s", "highload-wallet-v2.fif", "wallet", strconv.FormatUint(uint64(subwalletID), 10), "wallet-orders.txt"}

	if bounceable {
		args = append(args, []string{"-b"}...)
	} else {
		args = append(args, []string{"-n"}...)
	}

	args = append(args, []string{"-t", strconv.FormatUint(uint64(timeout), 10)}...)
	args = append(args, []string{"-m", strconv.FormatUint(uint64(mode), 10)}...)

	reader, boc, err := f.wallet(args, privateKey, workchain, rawAddress, &subwalletID, nil, orders, "wallet")

	// read query id
	queryID, err := f.readQueryID(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("bad query id: %w", err)
	}

	return queryID, boc, err
}

// HighloadWalletV2One ...
func (f *Fift) HighloadWalletV2One(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, subwalletID uint32, destination string, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, []byte, error) {
	// command: fift -s highload-wallet-v2-one.fif <filename-base> <dest-addr> <subwallet-id> <amount> [-x <extra-amount>*<extra-currency-id>] [-n|-b] [-t<timeout>] [-B <body-boc>] [-C <comment>] [<savefile>]
	args := []string{"-s", "highload-wallet-v2-one.fif", "wallet", destination, strconv.FormatUint(uint64(subwalletID), 10), amount}

	if bounceable {
		args = append(args, []string{"-b"}...)
	} else {
		args = append(args, []string{"-n"}...)
	}

	args = append(args, []string{"-t", strconv.FormatUint(uint64(timeout), 10)}...)

	if bodyBoc != nil {
		args = append(args, []string{"-B", "body.boc"}...)
	}

	if comment != "" {
		args = append(args, []string{"-C", comment}...)
	}

	args = append(args, []string{"-m", strconv.FormatUint(uint64(mode), 10)}...)

	reader, boc, err := f.wallet(args, privateKey, workchain, rawAddress, &subwalletID, bodyBoc, nil, "wallet")

	// read query id
	queryID, err := f.readQueryID(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("bad query id: %w", err)
	}

	return queryID, boc, err
}

// Wallet (r3)...
func (f *Fift) Wallet(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, seqno uint32, amount string, bounceable bool, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	// command: fift -s wallet.fif <filename-base> <dest-addr> <seqno> <amount> [-x <extra-amount>*<extra-currency-id>] [-n|-b] [-B <body-boc>] [-C <comment>] [<savefile>]
	args := []string{"-s", "wallet.fif", "wallet", destination, strconv.FormatUint(uint64(seqno), 10), amount}

	if bounceable {
		args = append(args, []string{"-b"}...)
	} else {
		args = append(args, []string{"-n"}...)
	}

	if bodyBoc != nil {
		args = append(args, []string{"-B", "body.boc"}...)
	}

	if comment != "" {
		args = append(args, []string{"-C", comment}...)
	}

	args = append(args, []string{"-m", strconv.FormatUint(uint64(mode), 10)}...)

	_, boc, err := f.wallet(args, privateKey, workchain, rawAddress, nil, bodyBoc, nil, "wallet")
	return boc, err
}

// WalletV2 (r2) ...
func (f *Fift) WalletV2(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	// command: fift -s wallet-v2.fif <filename-base> <dest-addr> <seqno> <amount> [-x <extra-amount>*<extra-currency-id>] [-n|-b] [-t<timeout>] [-B <body-boc>] [-C <comment>] [<savefile>]
	args := []string{"-s", "wallet-v2.fif", "wallet", destination, strconv.FormatUint(uint64(seqno), 10), amount}

	if bounceable {
		args = append(args, []string{"-b"}...)
	} else {
		args = append(args, []string{"-n"}...)
	}

	args = append(args, []string{"-t", strconv.FormatUint(uint64(timeout), 10)}...)

	if bodyBoc != nil {
		args = append(args, []string{"-B", "body.boc"}...)
	}

	if comment != "" {
		args = append(args, []string{"-C", comment}...)
	}

	args = append(args, []string{"-m", strconv.FormatUint(uint64(mode), 10)}...)

	_, boc, err := f.wallet(args, privateKey, workchain, rawAddress, nil, bodyBoc, nil, "wallet")
	return boc, err
}

// WalletV3 (r2) ...
func (f *Fift) WalletV3(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, subwalletID uint32, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	// command: fift -s wallet-v3.fif <filename-base> <dest-addr> <subwallet-id> <seqno> <amount> [-x <extra-amount>*<extra-currency-id>] [-n|-b] [-t<timeout>] [-B <body-boc>] [-C <comment>] [<savefile>]
	args := []string{"-s", "wallet-v3.fif", "wallet", destination, strconv.FormatUint(uint64(subwalletID), 10), strconv.FormatUint(uint64(seqno), 10), amount}

	if bounceable {
		args = append(args, []string{"-b"}...)
	} else {
		args = append(args, []string{"-n"}...)
	}

	args = append(args, []string{"-t", strconv.FormatUint(uint64(timeout), 10)}...)

	if bodyBoc != nil {
		args = append(args, []string{"-B", "body.boc"}...)
	}

	if comment != "" {
		args = append(args, []string{"-C", comment}...)
	}

	args = append(args, []string{"-m", strconv.FormatUint(uint64(mode), 10)}...)

	_, boc, err := f.wallet(args, privateKey, workchain, rawAddress, &subwalletID, bodyBoc, nil, "wallet")
	return boc, err
}

// WalletV4 (r1) ...
func (f *Fift) WalletV4(privateKey *ed25519.PrivateKey, workchain int64, rawAddress []byte, destination string, subwalletID uint32, seqno uint32, amount string, bounceable bool, timeout int32, bodyBoc []byte, comment string, mode uint8) ([]byte, error) {
	// command: fift -s wallet-v4.fif <filename-base> <dest-addr> <subwallet-id> <seqno> <amount> [-x <extra-amount>*<extra-currency-id>] [-n|-b] [-t<timeout>] [-B <body-boc>] [-C <comment>] [<savefile>]
	args := []string{"-s", "wallet-v4.fif", "wallet", destination, strconv.FormatUint(uint64(subwalletID), 10), strconv.FormatUint(uint64(seqno), 10), amount}

	if bounceable {
		args = append(args, []string{"-b"}...)
	} else {
		args = append(args, []string{"-n"}...)
	}

	args = append(args, []string{"-t", strconv.FormatUint(uint64(timeout), 10)}...)

	if bodyBoc != nil {
		args = append(args, []string{"-B", "body.boc"}...)
	}

	if comment != "" {
		args = append(args, []string{"-C", comment}...)
	}

	args = append(args, []string{"-m", strconv.FormatUint(uint64(mode), 10)}...)

	_, boc, err := f.wallet(args, privateKey, workchain, rawAddress, &subwalletID, bodyBoc, nil, "wallet")
	return boc, err
}

// ValidatorElectReq ...
func (f *Fift) ValidatorElectReq(walletAddress string, electionDate uint64, maxFactor float64, adnlAddress string) ([]byte, error) {
	// command: fift -s validator-elect-req.fif <wallet-addr> <elect-utime> <max-factor> <adnl-addr> [<savefile>]
	args := []string{"-s", "validator-elect-req.fif", walletAddress, strconv.FormatUint(electionDate, 10), strconv.FormatFloat(maxFactor, 'f', -1, 64), adnlAddress, "validator-to-sign.bin"}

	fd, err := executer.NewWorkDir(f.executer, f.getDir())
	if err != nil {
		return nil, fmt.Errorf("executer.NewWorkDir() error %w", err)
	}
	defer func() {
		if err := fd.Remove(); err != nil {
			f.logger.Error(err, "remove workdir")
		}
	}()

	_, err = fd.Exec(args)
	if err != nil {
		return nil, fmt.Errorf("f.execInWorkdir() error: %w", err)
	}

	var response []byte
	// read boc
	if response, err = fd.ReadFile("validator-to-sign.bin"); err != nil {
		return nil, fmt.Errorf("fd.ReadFile() error with filename = %s: %w", "validator-to-sign.bin", err)
	}

	return response, nil
}

// ValidatorElectSigned ...
func (f *Fift) ValidatorElectSigned(walletAddress string, electionDate uint64, maxFactor float64, adnlAddress string, validatorPubKey, validatorSignature []byte) ([]byte, error) {
	// command: fift -s validator-elect-signed.fif <wallet-addr> <elect-utime> <max-factor> <adnl-addr> <validator-pubkey> <validator-signature> [<savefile>]
	args := []string{"-s", "validator-elect-signed.fif", walletAddress, strconv.FormatUint(electionDate, 10), strconv.FormatFloat(maxFactor, 'f', -1, 64), adnlAddress, base64.StdEncoding.EncodeToString(validatorPubKey), base64.StdEncoding.EncodeToString(validatorSignature), "validator-query.boc"}

	fd, err := executer.NewWorkDir(f.executer, f.getDir())
	if err != nil {
		return nil, fmt.Errorf("executer.NewWorkDir() error %w", err)
	}
	defer func() {
		if err := fd.Remove(); err != nil {
			f.logger.Error(err, "remove workdir")
		}
	}()

	_, err = fd.Exec(args)
	if err != nil {
		return nil, fmt.Errorf("f.execInWorkdir() error: %w", err)
	}

	var response []byte

	// read boc
	if response, err = fd.ReadFile("validator-query.boc"); err != nil {
		return nil, fmt.Errorf("fd.ReadFile() error with filename = %s: %w", "validator-query.boc", err)
	}

	return response, nil
}

// RecoverStake ...
func (f *Fift) RecoverStake() ([]byte, error) {
	// command: fift -s recover-stake.fif [<savefile>]
	args := []string{"-s", "recover-stake.fif", "recover-query.boc"}

	fd, err := executer.NewWorkDir(f.executer, f.getDir())
	if err != nil {
		return nil, fmt.Errorf("executer.NewWorkDir() error %w", err)
	}

	defer func() {
		if err := fd.Remove(); err != nil {
			f.logger.Error(err, "remove workdir")
		}
	}()

	_, err = fd.Exec(args)
	if err != nil {
		return nil, fmt.Errorf("f.execInWorkdir() error: %w", err)
	}

	var response []byte

	// read boc
	if response, err = fd.ReadFile("recover-query.boc"); err != nil {
		return nil, fmt.Errorf("fd.ReadFile() error with filename = %s: %w", "recover-query.boc", err)
	}

	return response, nil
}

// NewFift ...
func NewFift(path string, args []string, timeout time.Duration, logger logr.Logger) (*Fift, error) {
	e, err := executer.NewExecuter(path, args, timeout, logger)
	if err != nil {
		return nil, fmt.Errorf("can't create fift executor: %w", err)
	}

	fift := Fift{
		executer: e,
		logger:   logger,
	}
	return &fift, nil
}
