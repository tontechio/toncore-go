package crc

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/howeyc/crc16"
)

func GetCRC16(data []byte) []byte {
	n := crc16.Checksum(data, crc16.CCITTFalseTable)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, n)
	return h
}

func GetCRC32C(data []byte) []byte {
	n := crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
	h := make([]byte, 4)
	binary.LittleEndian.PutUint32(h, n)
	return h
}
