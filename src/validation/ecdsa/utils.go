package ecdsa

import (
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// modNScalarToField converts a scalar modulo the group order to a field value.
func modNScalarToField(v *secp.ModNScalar) secp.FieldVal {
	var buf [32]byte
	v.PutBytes(&buf)
	var fv secp.FieldVal
	fv.SetBytes(&buf)
	return fv
}

var orderAsFieldVal = func() *secp.FieldVal {
		var f secp.FieldVal
		f.SetByteSlice(secp.Params().N.Bytes())
		return &f
	}()
