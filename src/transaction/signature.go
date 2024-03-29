package transaction

import (
	"errors"
	"fmt"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Signature struct {
	r secp.ModNScalar
	s secp.ModNScalar
}

// NewSignature instantiates a new signature given some r and s values.
func NewSignature(r, s secp.ModNScalar) *Signature {
    return &Signature{r:r, s:s}
}

var (
	one = big.NewInt(1)

	// oneInitializer is used to fill a byte slice with byte 0x01.  It is provided
	// here to avoid the need to create it multiple times.
	oneInitializer = []byte{0x01}
)

const (
	// MinSigLen is the minimum length of a DER encoded signature and is when both R
	// and S are 1 byte each.
	// 0x30 + <1-byte> + 0x02 + 0x01 + <byte> + 0x2 + 0x01 + <byte>
	MinSigLen = 8

	// MaxSigLen is the maximum length of a DER encoded signature and is
	// when both R and S are 33 bytes each.  It is 33 bytes because a
	// 256-bit integer requires 32 bytes and an additional leading null byte
	// might be required if the high bit is set in the value.
	//
	// 0x30 + <1-byte> + 0x02 + 0x21 + <33 bytes> + 0x2 + 0x21 + <33 bytes>
	MaxSigLen = 72
)

var (
	errNegativeValue          = errors.New("value may be interpreted as negative")
	errExcessivelyPaddedValue = errors.New("value is excessively padded")
)

func canonicalPadding(b []byte) error {
	switch {
	case b[0]&0x80 == 0x80:
		return errNegativeValue
	case len(b) > 1 && b[0] == 0x00 && b[1]&0x80 != 0x80:
		return errExcessivelyPaddedValue
	default:
		return nil
	}
}


func parseSig(sigStr []byte, der bool) (*Signature, error) {
	// Originally this code used encoding/asn1 in order to parse the
	// signature, but a number of problems were found with this approach.
	// Despite the fact that signatures are stored as DER, the difference
	// between go's idea of a bignum (and that they have sign) doesn't agree
	// with the openssl one (where they do not). The above is true as of
	// Go 1.1. In the end it was simpler to rewrite the code to explicitly
	// understand the format which is this:
	// 0x30 <length of whole message> <0x02> <length of R> <R> 0x2
	// <length of S> <S>.

	// The signature must adhere to the minimum and maximum allowed length.
	totalSigLen := len(sigStr)
	if totalSigLen < MinSigLen {
		return nil, errors.New("malformed signature: too short")
	}
	if der && totalSigLen > MaxSigLen {
		return nil, errors.New("malformed signature: too long")
	}

	// 0x30
	index := 0
	if sigStr[index] != 0x30 {
		return nil, errors.New("malformed signature: no header magic")
	}
	index++
	// length of remaining message
	siglen := sigStr[index]
	index++

	// siglen should be less than the entire message and greater than
	// the minimal message size.
	if int(siglen+2) > len(sigStr) || int(siglen+2) < MinSigLen {
		return nil, errors.New("malformed signature: bad length")
	}
	// trim the slice we're working on so we only look at what matters.
	sigStr = sigStr[:siglen+2]

	// 0x02
	if sigStr[index] != 0x02 {
		return nil,
			errors.New("malformed signature: no 1st int marker")
	}
	index++

	// Length of signature R.
	rLen := int(sigStr[index])
	// must be positive, must be able to fit in another 0x2, <len> <s>
	// hence the -3. We assume that the length must be at least one byte.
	index++
	if rLen <= 0 || rLen > len(sigStr)-index-3 {
		return nil, errors.New("malformed signature: bogus R length")
	}

	// Then R itself.
	rBytes := sigStr[index : index+rLen]
	if der {
		switch err := canonicalPadding(rBytes); err {
		case errNegativeValue:
			return nil, errors.New("signature R is negative")
		case errExcessivelyPaddedValue:
			return nil, errors.New("signature R is excessively padded")
		}
	}

	// Strip leading zeroes from R.
	for len(rBytes) > 0 && rBytes[0] == 0x00 {
		rBytes = rBytes[1:]
	}

	// R must be in the range [1, N-1].  Notice the check for the maximum number
	// of bytes is required because SetByteSlice truncates as noted in its
	// comment so it could otherwise fail to detect the overflow.
	var r secp.ModNScalar
	if len(rBytes) > 32 {
		str := "invalid signature: R is larger than 256 bits"
		return nil, errors.New(str)
	}
	if overflow := r.SetByteSlice(rBytes); overflow {
		str := "invalid signature: R >= group order"
		return nil, errors.New(str)
	}
	if r.IsZero() {
		str := "invalid signature: R is 0"
		return nil, errors.New(str)
	}
	index += rLen
	// 0x02. length already checked in previous if.
	if sigStr[index] != 0x02 {
		return nil, errors.New("malformed signature: no 2nd int marker")
	}
	index++

	// Length of signature S.
	sLen := int(sigStr[index])
	index++
	// S should be the rest of the string.
	if sLen <= 0 || sLen > len(sigStr)-index {
		return nil, errors.New("malformed signature: bogus S length")
	}

	// Then S itself.
	sBytes := sigStr[index : index+sLen]
	if der {
		switch err := canonicalPadding(sBytes); err {
		case errNegativeValue:
			return nil, errors.New("signature S is negative")
		case errExcessivelyPaddedValue:
			return nil, errors.New("signature S is excessively padded")
		}
	}

	// Strip leading zeroes from S.
	for len(sBytes) > 0 && sBytes[0] == 0x00 {
		sBytes = sBytes[1:]
	}

	// S must be in the range [1, N-1].  Notice the check for the maximum number
	// of bytes is required because SetByteSlice truncates as noted in its
	// comment so it could otherwise fail to detect the overflow.
	var s secp.ModNScalar
	if len(sBytes) > 32 {
		str := "invalid signature: S is larger than 256 bits"
		return nil, errors.New(str)
	}
	if overflow := s.SetByteSlice(sBytes); overflow {
		str := "invalid signature: S >= group order"
		return nil, errors.New(str)
	}
	if s.IsZero() {
		str := "invalid signature: S is 0"
		return nil, errors.New(str)
	}
	index += sLen

	// sanity check length parsing
	if index != len(sigStr) {
		return nil, fmt.Errorf("malformed signature: bad final length %v != %v",
			index, len(sigStr))
	}

	return NewSignature(r, s), nil

}

func checkHashTypeEncoding(hashType SigHashType) error {
	sigHashType := hashType & ^SigHashAnyOneCanPay
	if sigHashType < SigHashAll || sigHashType > SigHashSingle {
		str := fmt.Sprintf("invalid hash type 0x%x", hashType)
        return errors.New(str)
	}
	return nil
}


func parseSigAndPubkey(pkBytes, fullSigBytes []byte) (*secp.PublicKey, *Signature, SigHashType, error) {
	hashType := SigHashType(fullSigBytes[len(fullSigBytes)-1])
	sigBytes := fullSigBytes[:len(fullSigBytes)-1]
	if err := checkHashTypeEncoding(hashType); err != nil {
		return nil, nil, 0, err
	}

	// parse the public key
	pubKey, err := secp.ParsePubKey(pkBytes)
	if err != nil {
		return nil, nil, 0, err
	}

	// parse the signature 
    // we assume that every signature is in DER format
	var signature *Signature
	//if strictEncoding {
		signature, err = parseSig(sigBytes, true)
	//} else {
	//	signature, err = parseSig(sigBytes, false)
	// }
	if err != nil {
		return nil, nil, 0, err
	}

	return pubKey, signature, hashType, nil
}

func Verify(sig *Signature, hash []byte, pubKey *secp.PublicKey) bool {
	if sig.r.IsZero() || sig.s.IsZero() {
		return false
	}

	// Step 2.
	//
	// e = H(m)
	var e secp.ModNScalar
	e.SetByteSlice(hash)

	// Step 3.
	//
	// w = S^-1 mod N
	w := new(secp.ModNScalar).InverseValNonConst(&sig.s)

	// Step 4.
	//
	// u1 = e * w mod N
	// u2 = R * w mod N
	u1 := new(secp.ModNScalar).Mul2(&e, w)
	u2 := new(secp.ModNScalar).Mul2(&sig.r, w)

	// Step 5.
	//
	// X = u1G + u2Q
	var X, Q, u1G, u2Q secp.JacobianPoint
	pubKey.AsJacobian(&Q)
	secp.ScalarBaseMultNonConst(u1, &u1G)
	secp.ScalarMultNonConst(u2, &Q, &u2Q)
	secp.AddNonConst(&u1G, &u2Q, &X)

	// Step 6.
	//
	// Fail if X is the point at infinity
	if (X.X.IsZero() && X.Y.IsZero()) || X.Z.IsZero() {
		return false
	}

	// Step 7.
	//
	// z = (X.z)^2 mod P (X.z is the z coordinate of X)
	z := new(secp.FieldVal).SquareVal(&X.Z)

	// Step 8.
	//
	// Verified if R * z == X.x (mod P)
	sigRModP := modNScalarToField(&sig.r)
	result := new(secp.FieldVal).Mul2(&sigRModP, z).Normalize()
	if result.Equals(&X.X) {
		return true
	}

	// Step 9.
	//
	// Fail if R + N >= P
	if sigRModP.IsGtOrEqPrimeMinusOrder() {
		return false
	}

	// Step 10.
	//
	// Verified if (R + N) * z == X.x (mod P)
	sigRModP.Add(orderAsFieldVal)
	result.Mul2(&sigRModP, z).Normalize()
	return result.Equals(&X.X)
}
