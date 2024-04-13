package sighash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/humblenginr/btc-miner/utils"
	"github.com/humblenginr/btc-miner/transaction"
)

type SigHashType uint32

const (
	SigHashDefault      SigHashType = 0x00
	SigHashOld          SigHashType = 0x0
	SigHashAll          SigHashType = 0x1
	SigHashNone         SigHashType = 0x2
	SigHashSingle       SigHashType = 0x3
	SigHashAnyOneCanPay SigHashType = 0x80

	sigHashMask = 0x1f
)

func CheckHashTypeEncoding(hashType SigHashType) error {
	sigHashType := hashType & ^SigHashAnyOneCanPay
	if sigHashType < SigHashAll || sigHashType > SigHashSingle {
		str := fmt.Sprintf("invalid hash type 0x%x", hashType)
        return errors.New(str)
	}
	return nil
}

// calcSignatureHash computes the signature hash for the specified input of the
// target transaction observing the desired signature hash type.
// it works only for non-segwit transactions
// https://wiki.bitcoinsv.io/index.php/OP_CHECKSIG#:~:text=OP_CHECKSIG%20is%20an%20opcode%20that,signature%20check%20passes%20or%20fails
func CalcSignatureHash(sigScript []byte, hashType SigHashType, tx *transaction.Transaction, idx int) []byte {
	if hashType&sigHashMask == SigHashSingle && idx >= len(tx.Vout) {
		var hash [32]byte
		hash[0] = 0x01
		return hash[:]
	}

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
		fallthrough
	case SigHashOld:
		fallthrough
	case SigHashAll:
	}
	if hashType&SigHashAnyOneCanPay != 0 {
		txCopy.Vin = txCopy.Vin[idx : idx+1]
	}

	// double sha256 of the modified serialized
	// transaction with hash type appended.
	wbuf := bytes.NewBuffer(make([]byte, 0, txCopy.SerializeSize(false)+4))
	txCopy.Serialize(false, wbuf)
	binary.Write(wbuf, binary.LittleEndian, hashType)
	return utils.DoubleHash(wbuf.Bytes())
}

type SegwitSigHashes struct {
    HashPrevouts [32]byte
    HashSequence [32]byte
    HashOutputs [32]byte
}



func extractWitnessPubKeyHash(script []byte) []byte {
	// A pay-to-witness-pubkey-hash script is of the form:
	//   OP_0 OP_DATA_20 <20-byte-hash>
	if len(script) == 22 &&
		script[0] == 0 &&
		script[1] == 0x14 {

		return script[2:22]
	}

	return nil
}
func isWitnessPubKeyHashScript(script []byte) bool {
	return extractWitnessPubKeyHash(script) != nil
}

// Implementated using [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) as the reference
func CalcWitnessSignatureHash(subScript []byte, sigHashes *SegwitSigHashes,
	hashType SigHashType, tx *transaction.Transaction, idx int) ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0))
    var scratch [8]byte
    // First write out, then encode the transaction's version
    // number.
    binary.LittleEndian.PutUint32(scratch[:], uint32(tx.Version))
    w.Write(scratch[:4])
    // Next write out the possibly pre-calculated hashes for the
    // sequence numbers of all inputs, and the hashes of the
    // previous outs for all outputs.
    var zeroHash [32]byte
    // If anyone can pay isn't active, then we can use the cached
    // hashPrevOuts, otherwise we just write zeroes for the prev
    // outs.
    if hashType&SigHashAnyOneCanPay == 0 {
        w.Write(sigHashes.HashPrevouts[:])
    } else {
        w.Write(zeroHash[:])
    }
    // If the sighash isn't anyone can pay, single, or none, the
    // use the cached hash sequences, otherwise write all zeroes
    // for the hashSequence.
    if hashType&SigHashAnyOneCanPay == 0 &&
        hashType&sigHashMask != SigHashSingle &&
        hashType&sigHashMask != SigHashNone {
        w.Write(sigHashes.HashSequence[:])
    } else {
        w.Write(zeroHash[:])
    }
    txIn := tx.Vin[idx]
    // Next, write the outpoint being spent.
    prevOutHash,_ := hex.DecodeString(txIn.Txid)
    // have to reverse it
    prevOutHash = utils.ReverseBytes(prevOutHash)
    w.Write(prevOutHash[:])
    var bIndex [4]byte
    binary.LittleEndian.PutUint32(
        bIndex[:], uint32(txIn.Vout),
    )
    w.Write(bIndex[:])
    // Next, write subscript
    if isWitnessPubKeyHashScript(subScript) {
    w.Write([]byte{0x19})
    w.Write([]byte{0x76}) // OP_DUP
    w.Write([]byte{0xa9}) // OP_HASH160
    w.Write([]byte{0x14}) // OP_DATA_20
    w.Write(extractWitnessPubKeyHash(subScript))
    w.Write([]byte{0x88}) // OP_EQUALVERIFY
    w.Write([]byte{0xac}) // OP_CHECKSIG
    }else {
        // For p2wsh outputs, and future outputs, the script
        // code is the original script, with all code
        // separators removed, serialized with a var int length
        // prefix.
        transaction.WriteVarBytes(w, subScript)
    }

    // Next, add the input amount, and sequence number of the input
    // being signed.
    binary.LittleEndian.PutUint64(scratch[:], uint64(txIn.PrevOut.Value))
    w.Write(scratch[:])
    binary.LittleEndian.PutUint32(scratch[:], uint32(txIn.Sequence))
    w.Write(scratch[:4])

    // If the current signature mode isn't single, or none, then we
    // can re-use the pre-generated hashoutputs sighash fragment.
    // Otherwise, we'll serialize and add only the target output
    // index to the signature pre-image.
    if hashType&sigHashMask != SigHashSingle &&
        hashType&sigHashMask != SigHashNone {

        w.Write(sigHashes.HashOutputs[:])
    } else if hashType&sigHashMask == SigHashSingle &&
        idx < len(tx.Vout) {
        tw := bytes.NewBuffer(make([]byte, 0))
        transaction.SerializeAndWriteTxOutput(tw, tx.Vout[idx])
        h := utils.DoubleHash(tw.Bytes())
        w.Write(h[:])
    } else {
        w.Write(zeroHash[:])
    }
    // Finally, write out the transaction's locktime, and the sig
    // hash type.
    binary.LittleEndian.PutUint32(scratch[:], tx.Locktime)
    w.Write(scratch[:4])
    binary.LittleEndian.PutUint32(scratch[:], uint32(hashType))
    w.Write(scratch[:4])

    sigHashBytes := utils.DoubleHash(w.Bytes())

	return sigHashBytes[:], nil
}
