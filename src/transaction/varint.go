package transaction

import (
	"encoding/binary"
	"io"
	"math"
)

// WriteVarBytes serializes a variable length byte array to w as a varInt
// containing the number of bytes, followed by the bytes themselves.
func WriteVarBytes(w io.Writer, bytes []byte) error {
	slen := uint64(len(bytes))
	err := WriteVarInt(w, slen)
	if err != nil {
		return err
	}
	_, err = w.Write(bytes)
	return err
}

// VarIntSerializeSize returns the number of bytes it would take to serialize
// val as a variable length integer.
func VarIntSerializeSize(val uint64) int {
	// The value is small enough to be represented by itself, so it's
	// just 1 byte.
	if val < 0xfd {
		return 1
	}

	// Discriminant 1 byte plus 2 bytes for the uint16.
	if val <= math.MaxUint16 {
		return 3
	}

	// Discriminant 1 byte plus 4 bytes for the uint32.
	if val <= math.MaxUint32 {
		return 5
	}

	// Discriminant 1 byte plus 8 bytes for the uint64.
	return 9
}

// WriteVarInt serializes val to w using a variable number of bytes depending
// on its value.
func WriteVarInt(w io.Writer, val uint64) error {
	if val < 0xfd {
        buffer := make([]byte, 1)
        buffer[0] = uint8(val)
        _, err := w.Write(buffer)
		return err
	}

	if val <= math.MaxUint16 {
        buffer := make([]byte, 1)
        buffer[0] = 0xfd
        _, err := w.Write(buffer)
        if err != nil {
            return err
        }
        buffer = make([]byte, 2)
        binary.LittleEndian.PutUint16(buffer,uint16(val))
        _, err = w.Write(buffer)
		return err
	}

	if val <= math.MaxUint32 {
        buffer := make([]byte, 1)
        buffer[0] = 0xfe
        _, err := w.Write(buffer)
        if err != nil {
            return err
        }
        buffer = make([]byte, 4)
        binary.LittleEndian.PutUint32(buffer,uint32(val))
        _, err = w.Write(buffer)
		return err
	}

        buffer := make([]byte, 1)
        buffer[0] = 0xff
        _, err := w.Write(buffer)
        if err != nil {
            return err
        }
        buffer = make([]byte, 8)
        binary.LittleEndian.PutUint64(buffer,uint64(val))
        _, err = w.Write(buffer)
		return err
}
