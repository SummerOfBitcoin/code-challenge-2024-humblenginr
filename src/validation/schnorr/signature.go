package schnorr

import (
	"errors"
	"fmt"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/humblenginr/btc-miner/utils"
	"github.com/humblenginr/btc-miner/validation/sighash"
)

// Signature is a type representing a Schnorr signature.
type Signature struct {
	r secp.FieldVal

	s secp.ModNScalar
}

// NewSignature instantiates a new signature given some r and s values.
func NewSignature(r *secp.FieldVal, s *secp.ModNScalar) *Signature {
	var sig Signature
	sig.r.Set(r).Normalize()
	sig.s.Set(s)
	return &sig
}

// ParsePubKey parses a public key for a koblitz curve from a bytestring into a
// btcec.Publickey, verifying that it is valid. It only supports public keys in
// the BIP-340 32-byte format.
func ParsePubKey(pubKeyStr []byte) (*secp.PublicKey, error) {
	if pubKeyStr == nil {
		err := fmt.Errorf("nil pubkey byte string")
		return nil, err
	}
	if len(pubKeyStr) != 32 {
		err := fmt.Errorf("bad pubkey byte string size (want %v, have %v)",
			32, len(pubKeyStr))
		return nil, err
	}

	var keyCompressed [secp.PubKeyBytesLenCompressed]byte
	keyCompressed[0] = secp.PubKeyFormatCompressedEven
	copy(keyCompressed[1:], pubKeyStr)

	return secp.ParsePubKey(keyCompressed[:])
}

// parseTaprootSigAndPubKey attempts to parse the public key and signature for
// a taproot spend that may be a keyspend or script path spend. This function
// returns an error if the pubkey is invalid, or the sig is.
func ParseSigAndPubkey(pkBytes, rawSig []byte,
) (*secp.PublicKey, *Signature, sighash.SigHashType, error) {
	pubKey, err := ParsePubKey(pkBytes)

	if err != nil {
		return nil, nil, 0, err
	}
	var (
		sig         *Signature
		sigHashType sighash.SigHashType
	)
	switch {
	case len(rawSig) == 64:
		sig, err = ParseSignature(rawSig)
		if err != nil {
			return nil, nil, 0, err
		}
		sigHashType = sighash.SigHashDefault

	case len(rawSig) == 64+1 && rawSig[64] != 0:
		sigHashType = sighash.SigHashType(rawSig[64])

		rawSig = rawSig[:64]
		sig, err = ParseSignature(rawSig)
		if err != nil {
			return nil, nil, 0, err
		}

	default:
		str := fmt.Sprintf("invalid sig len: %v", len(rawSig))
		return nil, nil, 0, errors.New(str)
	}

	return pubKey, sig, sigHashType, nil
}

func ParseSignature(sig []byte) (*Signature, error) {
	// The signature must be the correct length.
	sigLen := len(sig)
	if sigLen < 64 {
		str := fmt.Sprintf("malformed signature: too short: %d < %d", sigLen,
			64)
		return nil, errors.New(str)
	}
	if sigLen > 64 {
		str := fmt.Sprintf("malformed signature: too long: %d > %d", sigLen,
			64)
		return nil, errors.New(str)
	}

	var r secp.FieldVal
	if overflow := r.SetByteSlice(sig[0:32]); overflow {
		str := "invalid signature: r >= field prime"
		return nil, errors.New(str)
	}
	var s secp.ModNScalar
	if overflow := s.SetByteSlice(sig[32:64]); overflow {
		str := "invalid signature: s >= group order"
		return nil, errors.New(str)
	}

	return NewSignature(&r, &s), nil
}


// This is taken from btcd repository (https://github.com/btcsuite/btcd). I came to know that it is not necessary to validate schnorr signatures only after I implemented these.
func Verify(sig *Signature, hash []byte, pubKeyBytes []byte) bool {
	// The algorithm for producing a BIP-340 signature is described in
	// README.md and is reproduced here for reference:
	//
	// 1. Fail if m is not 32 bytes
	// 2. P = lift_x(int(pk)).
	// 3. r = int(sig[0:32]); fail is r >= p.
	// 4. s = int(sig[32:64]); fail if s >= n.
	// 5. e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
	// 6. R = s*G - e*P
	// 7. Fail if is_infinite(R)
	// 8. Fail if not hash_even_y(R)
	// 9. Fail is x(R) != r.
	// 10. Return success iff failure did not occur before reaching this point.

	// Step 1.
	//
	// Fail if m is not 32 bytes
	if len(hash) != 32 {
		return false
	}

	// Step 2.
	//
	// P = lift_x(int(pk))
	//
	// Fail if P is not a point on the curve
	pubKey, err := ParsePubKey(pubKeyBytes)
	if err != nil {
		return false
	}
	if !pubKey.IsOnCurve() {
		return false
	}

	// Step 3.
	//
	// Fail if r >= p
	//
	// Note this is already handled by the fact r is a field element.

	// Step 4.
	//
	// Fail if s >= n
	//
	// Note this is already handled by the fact s is a mod n scalar.

	// Step 5.
	//
	// e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
	var rBytes [32]byte
	sig.r.PutBytesUnchecked(rBytes[:])
	pBytes := SerializePubKey(pubKey)

	commitment := utils.TaggedHash(
		[]byte("BIP0340/challenge"), rBytes[:], pBytes, hash,
	)

	var e secp.ModNScalar
	e.SetBytes((*[32]byte)(commitment))

	// Negate e here so we can use AddNonConst below to subtract the s*G
	// point from e*P.
	e.Negate()

	// Step 6.
	//
	// R = s*G - e*P
	var P, R, sG, eP secp.JacobianPoint
	pubKey.AsJacobian(&P)
	secp.ScalarBaseMultNonConst(&sig.s, &sG)
	secp.ScalarMultNonConst(&e, &P, &eP)
	secp.AddNonConst(&sG, &eP, &R)

	// Step 7.
	//
	// Fail if R is the point at infinity
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		return false
	}

	// Step 8.
	//
	// Fail if R.y is odd
	//
	// Note that R must be in affine coordinates for this check.
	R.ToAffine()
	if R.Y.IsOdd() {
		return false
	}

	// Step 9.
	//
	// Verified if R.x == r
	//
	// Note that R must be in affine coordinates for this check.
	if !sig.r.Equals(&R.X) {
		return false
	}

	// Step 10.
	//
	// Return success iff failure did not occur before reaching this point.
	return true
}

// zeroArray zeroes the memory of a scalar array.
func zeroArray(a *[32]byte) {
	for i := 0; i < 32; i++ {
		a[i] = 0x00
	}
}

func SerializePubKey(pub *secp.PublicKey) []byte {
	pBytes := pub.SerializeCompressed()
	return pBytes[1:]
}
