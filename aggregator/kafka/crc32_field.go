package kafka

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sync"
)

type crcPolynomial int8

const (
	crcIEEE crcPolynomial = iota
	crcCastagnoli
)

var crc32FieldPool = sync.Pool{}

func acquireCrc32Field(polynomial crcPolynomial) *crc32Field {
	val := crc32FieldPool.Get()
	if val != nil {
		c := val.(*crc32Field)
		c.polynomial = polynomial
		return c
	}
	return newCRC32Field(polynomial)
}

func releaseCrc32Field(c *crc32Field) {
	crc32FieldPool.Put(c)
}

var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// crc32Field implements the pushEncoder and pushDecoder interfaces for calculating CRC32s.
type crc32Field struct {
	startOffset int
	polynomial  crcPolynomial
}

func (c *crc32Field) saveOffset(in int) {
	c.startOffset = in
}

func (c *crc32Field) reserveLength() int {
	return 4
}

func newCRC32Field(polynomial crcPolynomial) *crc32Field {
	return &crc32Field{polynomial: polynomial}
}

func (c *crc32Field) check(curOffset int, buf []byte) error {
	crc, err := c.crc(curOffset, buf)
	if err != nil {
		return err
	}

	expected := binary.BigEndian.Uint32(buf[c.startOffset:])
	if crc != expected {
		return PacketDecodingError{fmt.Sprintf("CRC didn't match expected %#x got %#x", expected, crc)}
	}

	return nil
}

func (c *crc32Field) crc(curOffset int, buf []byte) (uint32, error) {
	var tab *crc32.Table
	switch c.polynomial {
	case crcIEEE:
		tab = crc32.IEEETable
	case crcCastagnoli:
		tab = castagnoliTable
	default:
		return 0, PacketDecodingError{"invalid CRC type"}
	}
	return crc32.Checksum(buf[c.startOffset+4:curOffset], tab), nil
}
