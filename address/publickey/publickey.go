package publickey

import "github.com/tontechio/toncore-go/address/crc"

// Signature for public key
var Signature = []byte{0x3e, 0xe6}

// GetSigned returns public key with signature and crc
func GetSigned(publicKey []byte) []byte {
	pubSigned := append(Signature, publicKey...)
	pubSignedCrc := crc.GetCRC16(pubSigned)
	pubSigned = append(pubSigned, pubSignedCrc...)
	return pubSigned
}
