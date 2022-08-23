package address

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/tontechio/toncore-go"

	"github.com/tontechio/toncore-go/address/crc"
)

/*
ConvertAddress ...
A) "Raw": <decimal workchain_id>:<64 hexadecimal digits with address>
B) "User-friendly", which is obtained by first generating:
- one tag byte (0x11 for "bounceable" addresses, 0x51 for "non-bounceable"; add +0x80 if the address should not be accepted by software running in the production network)
- one byte containing a signed 8-bit integer with the workchain_id (0x00 for the basic workchain, 0xff for the masterchain)
- 32 bytes containing 256 bits of the smart-contract address inside the workchain (big-endian)
- 2 bytes containing CRC16-CCITT of the previous 34 bytes
*/
func ConvertAddress(workchain int64, rawAddress []byte, testnet, bounceable bool) []byte {
	tagByte := byte(0x51)
	if bounceable {
		tagByte = 0x11
	}
	if testnet {
		tagByte = tagByte + 0x80
	}
	address := append([]byte{tagByte, byte(workchain)}, rawAddress...)
	address = append(address, crc.GetCRC16(address)...)

	return address
}

/*
FillAddresses ...
A) "Raw": <decimal workchain_id>:<64 hexadecimal digits with address>
B) "User-friendly", which is obtained by first generating:
- one tag byte (0x11 for "bounceable" addresses, 0x51 for "non-bounceable"; add +0x80 if the address should not be accepted by software running in the production network)
- one byte containing a signed 8-bit integer with the workchain_id (0x00 for the basic workchain, 0xff for the masterchain)
- 32 bytes containing 256 bits of the smart-contract address inside the workchain (big-endian)
- 2 bytes containing CRC16-CCITT of the previous 34 bytes
*/
func FillAddresses(addr *toncore.TonAddress) *toncore.TonAddress {
	testnetNonBounceable := append([]byte{0x51 + 0x80, addr.Workchain}, addr.RawAddress...)
	addr.TestnetNonBounceable = append(testnetNonBounceable, crc.GetCRC16(testnetNonBounceable)...)

	testnetBounceable := append([]byte{0x11 + 0x80, addr.Workchain}, addr.RawAddress...)
	addr.TestnetBounceable = append(testnetBounceable, crc.GetCRC16(testnetBounceable)...)

	mainnetNonBounceable := append([]byte{0x51, addr.Workchain}, addr.RawAddress...)
	addr.MainnetNonBounceable = append(mainnetNonBounceable, crc.GetCRC16(mainnetNonBounceable)...)

	mainnetBounceable := append([]byte{0x11, addr.Workchain}, addr.RawAddress...)
	addr.MainnetBounceable = append(mainnetBounceable, crc.GetCRC16(mainnetBounceable)...)

	return addr
}

// Address for TON
type Address struct {
	Workchain int64
	Raw       []byte
}

// GetFriendly returns address in base64url
func (a Address) GetFriendly(testnet, bounceable bool) string {
	return base64.RawURLEncoding.EncodeToString(ConvertAddress(a.Workchain, a.Raw, testnet, bounceable))
}

// GetFullRawAddress returns address in raw+workchain format
func (a Address) GetFullRawAddress() []byte {
	workchain := make([]byte, 4)
	binary.BigEndian.PutUint32(workchain, uint32(a.Workchain))
	return append(a.Raw, workchain...)
}

// NewAddressFromFriendly returns raw address
func NewAddressFromFriendly(address string) (Address, error) {
	addr, err := base64.RawURLEncoding.DecodeString(address)
	if err != nil {
		return Address{}, fmt.Errorf("base64.RawURLEncoding.DecodeString error: %w", err)
	}

	// check len
	if len(addr) != 36 {
		return Address{}, fmt.Errorf("wrong address length: %v", len(addr))
	}

	// check crc
	if bytes.Equal(crc.GetCRC16(addr[:34]), addr[34:]) == false {
		return Address{}, fmt.Errorf("crc mismatch")
	}

	a := Address{
		Workchain: int64(addr[1]),
		Raw:       addr[2:34],
	}
	if a.Workchain == 255 { // 0xff
		a.Workchain = -1
	}

	return a, nil
}

// NewAddressFromFullRaw returns raw address
func NewAddressFromFullRaw(addr []byte) (Address, error) {
	// check len
	if len(addr) != 36 {
		return Address{}, fmt.Errorf("wrong address length: %v", len(addr))
	}

	// check crc
	a := Address{
		Workchain: int64(binary.BigEndian.Uint32(addr[32:])),
		Raw:       addr[:32],
	}
	if a.Workchain == 4294967295 { // 0xffffffff
		a.Workchain = -1
	}

	return a, nil
}

// IsEqual compares two addresses
func IsEqual(a, b string) (bool, error) {
	aAddr, err := NewAddressFromFriendly(a)
	if err != nil {
		return false, fmt.Errorf("'%v' error: %w", a, err)
	}

	bAddr, err := NewAddressFromFriendly(b)
	if err != nil {
		return false, fmt.Errorf("'%v' error: %w", b, err)
	}

	return bytes.Equal(aAddr.Raw, bAddr.Raw) && aAddr.Workchain == bAddr.Workchain, nil
}
