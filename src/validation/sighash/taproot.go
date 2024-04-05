package sighash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

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

// sigHashExtFlag represents the sig hash extension flag as defined in BIP 341.
// Extensions to the base sighash algorithm will be appended to the base
// sighash digest.
type sigHashExtFlag uint8

const (
	// baseSigHashExtFlag is the base extension flag. This adds no changes
	// to the sighash digest message. This is used for segwit v1 spends,
	// a.k.a the tapscript keyspend path.
	baseSigHashExtFlag sigHashExtFlag = 0

	// tapscriptSighashExtFlag is the extension flag defined by tapscript
	// base leaf version spend define din BIP 342. This augments the base
	// sighash by including the tapscript leaf hash, the key version, and
	// the code separator position.
	tapscriptSighashExtFlag sigHashExtFlag = 1
)

// taprootSigHashOptions houses a set of functional options that may optionally
// modify how the taproot/script sighash digest algorithm is implemented.
type taprootSigHashOptions struct {
	// extFlag denotes the current message digest extension being used. For
	// top-level script spends use a value of zero, while each tapscript
	// version can define its own values as well.
	extFlag sigHashExtFlag

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

// WithAnnex is a functional option that allows the caller to specify the
// existence of an annex in the final witness stack for the taproot/tapscript
// spends.
func WithAnnex(annex []byte) TaprootSigHashOption {
	return func(o *taprootSigHashOptions) {
		var b bytes.Buffer
		_ = transaction.WriteVarBytes(&b,  annex)
		o.annexHash = b.Bytes()
	}
}

// writeDigestExtensions writes out the sighash message extension defined by the
// current active sigHashExtFlags.
func (t *taprootSigHashOptions) writeDigestExtensions(w io.Writer) error {
	switch t.extFlag {
	// The base extension, used for tapscript keypath spends doesn't modify
	// the digest at all.
	case baseSigHashExtFlag:
		return nil

	// The tapscript base leaf version extension adds the leaf hash, key
	// version, and code separator position to the final digest.
	case tapscriptSighashExtFlag:
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
	}

	return nil
}

// defaultTaprootSighashOptions returns the set of default sighash options for
// taproot execution.
func defaultTaprootSighashOptions() *taprootSigHashOptions {
	return &taprootSigHashOptions{}
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

func CalcTaprootSignatureHash(sigHashes *TaprootSigHashes, hType SigHashType,
	tx *transaction.Transaction, idx int,
	sigHashOpts ...TaprootSigHashOption) ([]byte, error) {
	opts := defaultTaprootSighashOptions()
	for _, sigHashOpt := range sigHashOpts {
		sigHashOpt(opts)
	}

	// If a valid sighash type isn't passed in, then we'll exit early.
	if !isValidTaprootSigHash(hType) {
		// TODO(roasbeef): use actual errr here
		return nil, fmt.Errorf("invalid taproot sighash type: %v", hType)
	}

	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx > len(tx.Vin)-1 {
		return nil, fmt.Errorf("idx %d but %d txins", idx, len(tx.Vin))
	}

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature hash for this transaction.
	var sigMsg bytes.Buffer

	// The final sighash always has a value of 0x00 prepended to it, which
	// is called the sighash epoch.
	sigMsg.WriteByte(0x00)

	// First, we write the hash type encoded as a single byte.
	if err := sigMsg.WriteByte(byte(hType)); err != nil {
		return nil, err
	}

	// Next we'll write out the transaction specific data which binds the
	// outer context of the sighash.
	err := binary.Write(&sigMsg, binary.LittleEndian, tx.Version)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&sigMsg, binary.LittleEndian, tx.Locktime)
	if err != nil {
		return nil, err
	}

	// If sighash isn't anyone can pay, then we'll include all the
	// pre-computed midstate digests in the sighash.
	if hType&SigHashAnyOneCanPay != SigHashAnyOneCanPay {
		sigMsg.Write(sigHashes.HashPrevoutsV1[:])
		sigMsg.Write(sigHashes.HashInputAmountsV1[:])
		sigMsg.Write(sigHashes.HashInputScriptsV1[:])
		sigMsg.Write(sigHashes.HashSequenceV1[:])
	}

	// If this is sighash all, or its taproot alias (sighash default),
	// then we'll also include the pre-computed digest of all the outputs
	// of the transaction.
	if hType&SigHashSingle != SigHashSingle &&
		hType&SigHashSingle != SigHashNone {

		sigMsg.Write(sigHashes.HashOutputsV1[:])
	}

	// Next, we'll write out the relevant information for this specific
	// input.
	//
	// The spend type is computed as the (ext_flag*2) + annex_present. We
	// use this to bind the extension flag (that BIP 342 uses), as well as
	// the annex if its present.
	input := tx.Vin[idx]
	witnessHasAnnex := opts.annexHash != nil
	spendType := byte(opts.extFlag) * 2
	if witnessHasAnnex {
		spendType += 1
	}

	if err := sigMsg.WriteByte(spendType); err != nil {
		return nil, err
	}

	// If anyone can pay is active, then we'll write out just the specific
	// information about this input, given we skipped writing all the
	// information of all the inputs above.
	if hType&SigHashAnyOneCanPay == SigHashAnyOneCanPay {
		// We'll start out with writing this input specific information by
		// first writing the entire previous output.
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
		// Next, we'll write out the previous output (amt+script) being
		// spent itself.
        if err  := transaction.SerializeAndWriteTxOutput(&sigMsg, input.PrevOut); err != nil{
			return nil, err
        }
		// Finally, we'll write out the input sequence itself.
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
	// Now that we have the input specific information written, we'll
	// include the anex, if we have it.
	if witnessHasAnnex {
		sigMsg.Write(opts.annexHash)
	}
	// Finally, if this is sighash single, then we'll write out the
	// information for this given output.
	if hType&sigHashMask == SigHashSingle {
		// If this output doesn't exist, then we'll return with an error
		// here as this is an invalid sighash type for this input.
		if idx >= len(tx.Vout) {
			// TODO(roasbeef): real error here
			return nil, fmt.Errorf("invalid sighash type for input")
		}

		// Now that we know this is a valid sighash input combination,
		// we'll write out the information specific to this input.
		// We'll write the wire serialization of the output and compute
		// the sha256 in a single step.
		shaWriter := sha256.New()
		txOut := tx.Vout[idx]


        if err  := transaction.SerializeAndWriteTxOutput(shaWriter, txOut); err != nil{
			return nil, err
        }
		// With the digest obtained, we'll write this out into our
		// signature message.
		if _, err := sigMsg.Write(shaWriter.Sum(nil)); err != nil {
			return nil, err
		}
	}
	// Now that we've written out all the base information, we'll write any
	// message extensions (if they exist).
	if err := opts.writeDigestExtensions(&sigMsg); err != nil {
		return nil, err
	}
    // done according to BIP341 - https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
	sigHash := utils.TaggedHash([]byte("TapSighash"), sigMsg.Bytes())
	return sigHash[:], nil
}
