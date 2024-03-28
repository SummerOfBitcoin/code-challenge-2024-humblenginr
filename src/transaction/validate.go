package transaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/humblenginr/btc-miner/utils"
	"github.com/libs4go/crypto/hash160"
)


type SigHashType uint32

// Hash type bits from the end of a signature.
const (
	SigHashDefault      SigHashType = 0x00
	SigHashOld          SigHashType = 0x0
	SigHashAll          SigHashType = 0x1
	SigHashNone         SigHashType = 0x2
	SigHashSingle       SigHashType = 0x3
	SigHashAnyOneCanPay SigHashType = 0x80

	// sigHashMask defines the number of bits of the hash type which is used
	// to identify which outputs are signed.
	sigHashMask = 0x1f
)

func CommonValidation(t Transaction) bool {
    if (t.GetFees() < 0){
        return false
    } 
    return true

}

var orderAsFieldVal = func() *secp.FieldVal {
		var f secp.FieldVal
		f.SetByteSlice(secp.Params().N.Bytes())
		return &f
	}()

// modNScalarToField converts a scalar modulo the group order to a field value.
func modNScalarToField(v *secp.ModNScalar) secp.FieldVal {
	var buf [32]byte
	v.PutBytes(&buf)
	var fv secp.FieldVal
	fv.SetBytes(&buf)
	return fv
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


// sigScript is the prevOutsPubkeyscript

// CalcSignatureHash computes the signature hash for the specified input of the
// target transaction observing the desired signature hash type.
func calcSignatureHash(sigScript []byte, hashType SigHashType, tx *Transaction, idx int) []byte {
	if hashType&sigHashMask == SigHashSingle && idx >= len(tx.Vout) {
		var hash [32]byte
		hash[0] = 0x01
		return hash[:]
	}


	// Make a shallow copy of the transaction, zeroing out the script for
	// all inputs that are not currently being processed.
	txCopy := tx.ShallowCopy()
	for i := range txCopy.Vin {
		if i == idx {
			txCopy.Vin[idx].ScriptSig = hex.EncodeToString(sigScript)
		} else {
			txCopy.Vin[i].ScriptSig = ""
		}
	}

	switch hashType & sigHashMask {
	case SigHashNone:
		txCopy.Vout = txCopy.Vout[0:0] // Empty slice.
		for i := range txCopy.Vin {
			if i != idx {
				txCopy.Vin[i].Sequence = 0
			}
		}

	case SigHashSingle:
		// Resize output array to up to and including requested index.
		txCopy.Vout = txCopy.Vout[:idx+1]

		// All but current output get zeroed out.
		for i := 0; i < idx; i++ {
			txCopy.Vout[i].Value = -1
			txCopy.Vout[i].ScriptPubKey = ""
		}

		// Sequence on all other inputs is 0, too.
		for i := range txCopy.Vin {
			if i != idx {
				txCopy.Vin[i].Sequence = 0
			}
		}

	default:
		// Consensus treats undefined hashtypes like normal SigHashAll
		// for purposes of hash generation.
		fallthrough
	case SigHashOld:
		fallthrough
	case SigHashAll:
		// Nothing special here.
	}
	if hashType&SigHashAnyOneCanPay != 0 {
		txCopy.Vin = txCopy.Vin[idx : idx+1]
	}

	// The final hash is the double sha256 of both the serialized modified
	// transaction and the hash type (encoded as a 4-byte little-endian
	// value) appended.
	wbuf := bytes.NewBuffer(make([]byte, 0, txCopy.SerializeSize()+4))
	txCopy.Serialize(false, wbuf)
	binary.Write(wbuf, binary.LittleEndian, hashType)
	return utils.DoubleHash(wbuf.Bytes())
}



func ValidateP2PKH(tx Transaction, trIdx int) bool {
    x := strings.Split(tx.Vin[trIdx].ScriptSigAsm, " ")
    pubkey, _ := hex.DecodeString(x[len(x)-1])
    sigBytes, _ := hex.DecodeString(x[1])

    // 1. check the encoding of the signature and find the sighash type and also pubkey
    pk, sig,hashtype, err :=  parseBaseSigAndPubkey(pubkey, sigBytes)
    if err != nil {
        panic("Cannot parse signatuer and pub key: "+ err.Error())
    }
    // previousScriptPubKey is the prevout's 
    subscript := tx.Vin[trIdx].PrevOut.ScriptPubKey
    subscriptBytes, _ := hex.DecodeString(subscript)
    sighash := calcSignatureHash(subscriptBytes, hashtype, &tx, trIdx)
    return Verify(sig, sighash, pk)
}

func ValidateP2WPKH(i Vin, txn []byte) bool {
 
    // Verify public key hash
    pubkey, err := hex.DecodeString(i.Witness[1])
    if err != nil {
        panic(err)
    }
    // assuming that all scriptpubkey_asm are valid
    instrs := strings.Split(i.PrevOut.ScriptPubKeyAsm, " ")
    pubkeyhash := instrs[len(instrs) - 1]
    if(fmt.Sprintf("%x",hash160.Hash160(pubkey)) != pubkeyhash){
        return false
    }
    // check the signature
    signature, err := hex.DecodeString(i.Witness[0])
    if err != nil {
        panic(err)
    }
	h := sha256.New()
	h.Write(txn)
    println(CheckSignature(signature, pubkey, h.Sum(nil)))
    println(CheckSignature)
    return true
}

// pubkey - bytes value of pubkey
// signature - bytes value of signature
// txnhash - SHA256 of bytes value of txn
func CheckSignature(signature []byte, pubkey []byte, txnhash []byte) bool {
    // 1. Parse public key
    
    // 2. Parse signature
        // 3. Verify signature for the given transaction
    return true
}


