package sighash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"

	"github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
)

type TaprootSigHashes struct {
    HashPrevoutsV1 [32]byte
    HashSequenceV1 [32]byte
    HashInputAmountsV1 [32]byte
    HashInputScriptsV1 [32]byte
    HashOutputsV1 [32]byte
}


// taprootSigHashOptions houses a set of functional options that may optionally
// modify how the taproot/script sighash digest algorithm is implemented.
type taprootSigHashOptions struct {
	// extFlag denotes the current message digest extension being used. For
	// top-level script spends use a value of zero, while each tapscript
	// version can define its own values as well.
	extFlag uint8

	// annexHash is the sha256 hash of the annex with a compact size length
	// prefix: sha256(sizeOf(annex) || annex).
	annexHash []byte

	// tapLeafHash is the hash of the tapscript leaf as defined in BIP 341.
	// This should be h_tapleaf(version || compactSizeOf(script) || script).
	tapLeafHash []byte

	// keyVersion is the key version as defined in BIP 341. This is always
	// 0x00 for all currently defined leaf versions.
	keyVersion byte

	// codeSepPos is the op code position of the last code separator. This
	// is used for the BIP 342 sighash message extension.
	codeSepPos uint32
}
// writeDigestExtensions writes out the sighash message extension defined by the
// current active sigHashExtFlags.
func (t *taprootSigHashOptions) writeDigestExtensions(w io.Writer) error {
    if t.extFlag == 0 {
        return nil
    }
    if _, err := w.Write(t.tapLeafHash); err != nil {
        return err
    }
    if _, err := w.Write([]byte{t.keyVersion}); err != nil {
        return err
    }
    err := binary.Write(w, binary.LittleEndian, t.codeSepPos)
    if err != nil {
        return err
    }
	return nil
}

func newScriptSpendingTaprootSighashOptions(leafHash []byte, annex []byte) *taprootSigHashOptions {
    o := taprootSigHashOptions{}
    // this is according to BIP342, but we are assuming that all transactions are of base taproot version and setting it to 0
    var annexBuf bytes.Buffer
    var annexHash []byte
    if(annex != nil) {
        _ = transaction.WriteVarBytes(&annexBuf, annex)
        annexHash = utils.Hash(annexBuf.Bytes())
    }
    o.extFlag = 1
    o.tapLeafHash = leafHash
    o.keyVersion = 0
    o.annexHash = annexHash
    o.codeSepPos = math.MaxUint32
    return &o
}

func newKeyPathSpendingTaprootSighashOptions(annex []byte) *taprootSigHashOptions {
    var annexBuf bytes.Buffer
    var annexHash []byte
    if(annex != nil) {
        _ = transaction.WriteVarBytes(&annexBuf, annex)
        annexHash = utils.Hash(annexBuf.Bytes())
    }
    o := taprootSigHashOptions{}
    o.extFlag = 0
    o.tapLeafHash = nil
    o.keyVersion = 0
    o.annexHash = annexHash
    return &o

}

// TaprootSigHashOption defines a set of functional param options that can be
// used to modify the base sighash message with optional extensions.
type TaprootSigHashOption func(*taprootSigHashOptions)

// isValidTaprootSigHash returns true if the passed sighash is a valid taproot
// sighash.
func isValidTaprootSigHash(hashType SigHashType) bool {
	switch hashType {
	case SigHashDefault, SigHashAll, SigHashNone, SigHashSingle:
		fallthrough
	case 0x81, 0x82, 0x83:
		return true
	default:
		return false
	}
}

// this function is written using BIP341 specification
func CalcTaprootSignatureHash(sigHashes *TaprootSigHashes, hType SigHashType,
	tx *transaction.Transaction, idx int,
	leafHash []byte, annex []byte) ([]byte, error) {
    var opts *taprootSigHashOptions
    // we are assuming that the absence of leafHash means that we are doing keypath spending, else script spending
    if(leafHash == nil){
        opts = newKeyPathSpendingTaprootSighashOptions(annex)
    } else {
        opts = newScriptSpendingTaprootSighashOptions(leafHash,annex)
        fmt.Printf("INFO: Leafhash is not nil, opts: %v\n", opts)
    }
	// If a valid sighash type isn't passed in, then we'll exit early.
	if !isValidTaprootSigHash(hType) {
		return nil, fmt.Errorf("invalid taproot sighash type: %v", hType)
	}
	var sigMsg bytes.Buffer
	// sighash epoch - BIP341
	sigMsg.WriteByte(0x00)
	// First, we write the hash type encoded as a single byte.
	if err := sigMsg.WriteByte(byte(hType)); err != nil {
		return nil, err
	}
	err := binary.Write(&sigMsg, binary.LittleEndian, tx.Version)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&sigMsg, binary.LittleEndian, tx.Locktime)
	if err != nil {
		return nil, err
	}
    // if it is not sighash Anyonecanpay
	if hType&SigHashAnyOneCanPay != SigHashAnyOneCanPay {
		sigMsg.Write(sigHashes.HashPrevoutsV1[:])
		sigMsg.Write(sigHashes.HashInputAmountsV1[:])
		sigMsg.Write(sigHashes.HashInputScriptsV1[:])
		sigMsg.Write(sigHashes.HashSequenceV1[:])
	}
	if hType&SigHashSingle != SigHashSingle &&
		hType&SigHashSingle != SigHashNone {
		sigMsg.Write(sigHashes.HashOutputsV1[:])
	}
	// The spend type is (ext_flag*2) + annex_present (BIP341)
	input := tx.Vin[idx]
	witnessHasAnnex := opts.annexHash != nil
    fmt.Printf("witnessHasAnnex: %v\n", opts.annexHash)
	spendType := byte(opts.extFlag) * 2
	if witnessHasAnnex {
		spendType += 1
	}
	if err := sigMsg.WriteByte(spendType); err != nil {
		return nil, err
	}
	if hType&SigHashAnyOneCanPay == SigHashAnyOneCanPay {
        // write the entire prevout
        txid, err := hex.DecodeString(input.Txid)
        txid = utils.ReverseBytes(txid)
        if(err != nil){
            return nil,err
        }
        _, err = sigMsg.Write(txid)
        if err != nil {
            return nil, err
        }
        buf  := make([]byte, 4)
        binary.LittleEndian.PutUint32(buf[:4], uint32(input.Vout))
        _, err = sigMsg.Write(buf[:4])
		// previous output (amt+script) 
        if err  := transaction.SerializeAndWriteTxOutput(&sigMsg, input.PrevOut); err != nil{
			return nil, err
        }
		// input sequence
		err = binary.Write(&sigMsg, binary.LittleEndian, input.Sequence)
		if err != nil {
			return nil, err
		}
	} else {
		err := binary.Write(&sigMsg, binary.LittleEndian, uint32(idx))
		if err != nil {
			return nil, err
		}
	}
	if witnessHasAnnex {
		sigMsg.Write(opts.annexHash)
	}
	if hType&sigHashMask == SigHashSingle {
		if idx >= len(tx.Vout) {
			return nil, fmt.Errorf("invalid sighash type for input")
		}
		shaWriter := sha256.New()
		txOut := tx.Vout[idx]
        if err  := transaction.SerializeAndWriteTxOutput(shaWriter, txOut); err != nil{
			return nil, err
        }
		if _, err := sigMsg.Write(shaWriter.Sum(nil)); err != nil {
			return nil, err
		}
	}
	if err := opts.writeDigestExtensions(&sigMsg); err != nil {
		return nil, err
	}
    fmt.Printf("Signature hash before hashing: %x\n", sigMsg.Bytes())
    // done according to BIP341 - https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
	sigHash := utils.TaggedHash(utils.TagTapSighash, sigMsg.Bytes())
	return sigHash[:], nil
}
