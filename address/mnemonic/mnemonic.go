package mnemonic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/pbkdf2"

	"github.com/tontechio/toncore-go/address/publickey"
)

const (
	wordsCount      = 24
	pbkdfIterations = 100000
	pbkdfKeyLength  = 64
)

// Mnemonic struct
type Mnemonic struct {
	mnemonic   []string
	password   string
	privateKey ed25519.PrivateKey
}

// String returns comma-separated list
func (m *Mnemonic) String() string {
	return strings.Join(m.mnemonic, ",")
}

func (m *Mnemonic) normalized() string {
	return strings.Join(m.mnemonic, " ")
}

func (m *Mnemonic) entropy() []byte {
	mac := hmac.New(sha512.New, []byte(m.normalized()))
	mac.Write([]byte(m.password))
	return mac.Sum(nil)
}

func (m *Mnemonic) seed() []byte {
	return pbkdf2.Key(m.entropy(), []byte("TON default seed"), pbkdfIterations, pbkdfKeyLength, sha512.New)
}

func (m *Mnemonic) isBasicSeed() bool {
	seed := pbkdf2.Key(m.entropy(), []byte("TON seed version"), pbkdfIterations/256, pbkdfKeyLength, sha512.New)
	return seed[0] == 0
}

func (m *Mnemonic) isPasswordSeed() bool {
	seed := pbkdf2.Key(m.entropy(), []byte("TON fast seed version"), 1, pbkdfKeyLength, sha512.New)
	return seed[0] == 1
}

func (m *Mnemonic) newPrivateKey() ed25519.PrivateKey {
	seed := m.seed()
	privateKey := ed25519.NewKeyFromSeed(seed[0:32])
	return privateKey
}

// PublicKey returns ed25519 private key for mnemonic
func (m *Mnemonic) PrivateKey() ed25519.PrivateKey {
	if m.privateKey == nil {
		m.privateKey = m.newPrivateKey()
	}
	return m.privateKey
}

// PublicKey returns ed25519 public key for mnemonic
func (m *Mnemonic) PublicKey() ed25519.PublicKey {
	privateKey := m.PrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return publicKey
}

// PublicKeySigned adds signature to public key
func (m *Mnemonic) PublicKeySigned() []byte {
	publicKey := m.PublicKey()
	publicKeySigned := publickey.GetSigned(publicKey)
	return publicKeySigned
}

// Mnemonic returns mnemonic
func (m *Mnemonic) Mnemonic() []string {
	return m.mnemonic
}

func (m *Mnemonic) validate() error {
	if len(m.mnemonic) != wordsCount {
		return fmt.Errorf("invalid words count %d != %d", len(m.mnemonic), wordsCount)
	}

	for i, n := range m.mnemonic {
		n = strings.TrimSpace(n)
		m.mnemonic[i] = n
		if !isValid(n) {
			return fmt.Errorf("invalid word %s (%d)", n, i+1)
		}
	}

	return nil
}

// GenerateMnemonic generates mnemonic
func GenerateMnemonic(password string) (*Mnemonic, error) {
	maxIterations := 256 * 20
	for iteration := 0; iteration < maxIterations; iteration++ {
		var words []string
		var rnd [(wordsCount*11 + 7) / 8]byte
		rand.Read(rnd[:])
		for i := 0; i < wordsCount; i++ {
			wordI := 0
			for j := 0; j < 11; j++ {
				offset := i*11 + j
				if rnd[offset/8]&(1<<(offset&7)) != 0 {
					wordI |= 1 << j
				}
			}
			words = append(words, Bip39English[wordI])
		}
		mnemonicWithoutPassword, _ := NewMnemonic(words, "")
		if len(password) > 0 && !mnemonicWithoutPassword.isPasswordSeed() {
			continue
		}
		mnemonic, _ := NewMnemonic(words, password)
		if !mnemonic.isBasicSeed() {
			continue
		}
		if len(password) > 0 && mnemonicWithoutPassword.isBasicSeed() {
			continue
		}
		return mnemonic, nil
	}
	return nil, errors.New("failed to create a mnemonic")
}

// NewMnemonic creates mnemonic
func NewMnemonic(mnemonic []string, password string) (*Mnemonic, error) {
	m := Mnemonic{
		mnemonic: mnemonic,
		password: password,
	}

	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("mnemonic validate error: %w", err)
	}

	return &m, nil
}
