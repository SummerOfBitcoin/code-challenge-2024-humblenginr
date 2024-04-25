package validation

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
	"github.com/humblenginr/btc-miner/validation/schnorr"
)
type TapLeaf struct {
	// LeafVersion is the leaf version of this leaf.
	LeafVersion TapscriptLeafVersion

	// Script is the script to be validated based on the specified leaf
	// version.
	Script []byte
}

func NewTapLeaf(leafVersion TapscriptLeafVersion, script []byte) TapLeaf {
	return TapLeaf{
		LeafVersion: leafVersion,
		Script:      script,
	}
}

// computed as: h_tapleaf(leafVersion || compactSizeof(script) || script)
func (t TapLeaf) TapHash() [32]byte {
	var leafEncoding bytes.Buffer
	_ = leafEncoding.WriteByte(byte(t.LeafVersion))
	_ = transaction.WriteVarBytes(&leafEncoding, t.Script)

	return *utils.TaggedHash(utils.TagTapLeaf, leafEncoding.Bytes())
}

// tapBranchHash takes the raw tap hashes of the right and left nodes and
// hashes them into a branch
func tapBranchHash(l, r []byte) [32]byte {
	if bytes.Compare(l[:], r[:]) > 0 {
		l, r = r, l
	}

	return *utils.TaggedHash(
		utils.TagTapBranch, l[:], r[:],
	)
}

type TapscriptLeafVersion uint8

const (
	// BaseLeafVersion is the base tapscript leaf version. The semantics of
	// this version are defined in BIP 342.
	BaseLeafVersion TapscriptLeafVersion = 0xc0
)

type ControlBlock struct {
	Key *secp256k1.PublicKey
	OutputKeyYIsOdd bool
	LeafVersion TapscriptLeafVersion
	InclusionProof []byte
}

var ControlBlockMaxSize = 33 + 32 + 128



func ParseControlBlock(ctrlBlock []byte) (*ControlBlock, error) {
	switch {
	case len(ctrlBlock) < 33:
		str := fmt.Sprintf("min size is %v bytes, control block "+
			"is %v bytes", 33, len(ctrlBlock))
		return nil, errors.New(str)

	case len(ctrlBlock) > ControlBlockMaxSize:
		str := fmt.Sprintf("max size is %v, control block is %v bytes",
			ControlBlockMaxSize, len(ctrlBlock))
		return nil, errors.New(str)

	case (len(ctrlBlock)-33)%32 != 0:
		str := fmt.Sprintf("control block proof is not a multiple "+
			"of 32: %v", len(ctrlBlock)-33)
		return nil, errors.New(str)
	}

	leafVersion := TapscriptLeafVersion(ctrlBlock[0] & 0xfe)
	var yIsOdd bool
	if ctrlBlock[0]&0x01 == 0x01 {
		yIsOdd = true
	}
	rawKey := ctrlBlock[1:33]
	pubKey, err := schnorr.ParsePubKey(rawKey)
	if err != nil {
		return nil, err
	}
	proofBytes := ctrlBlock[33:]

	return &ControlBlock{
		Key:     pubKey,
		OutputKeyYIsOdd: yIsOdd,
		LeafVersion:     leafVersion,
		InclusionProof:  proofBytes,
	}, nil
}

// RootHash calculates the root hash of a tapscript given the revealed script.
func (c *ControlBlock) RootHash(revealedScript []byte) []byte {
	merkleAccumulator := NewTapLeaf(c.LeafVersion, revealedScript).TapHash()
	numNodes := len(c.InclusionProof) / 32
	for nodeOffset := 0; nodeOffset < numNodes; nodeOffset++ {
		leafOffset := 32 * nodeOffset
		nextNode := c.InclusionProof[leafOffset : leafOffset+32]

		merkleAccumulator = tapBranchHash(merkleAccumulator[:], nextNode)
	}

	return merkleAccumulator[:]
}

func ComputeTaprootOutputKey(pubKey *secp256k1.PublicKey,
	scriptRoot []byte) *secp256k1.PublicKey {
	internalKey, _ := schnorr.ParsePubKey(schnorr.SerializePubKey(pubKey))

	tapTweakHash := utils.TaggedHash(
		utils.TagTapTweak, schnorr.SerializePubKey(internalKey),
		scriptRoot,
	)
	var tweakScalar secp256k1.ModNScalar
	tweakScalar.SetBytes((*[32]byte)(tapTweakHash))

	var internalPoint secp256k1.JacobianPoint
	internalKey.AsJacobian(&internalPoint)

	var tPoint, taprootKey secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&tweakScalar, &tPoint)
	secp256k1.AddNonConst(&internalPoint, &tPoint, &taprootKey)

	taprootKey.ToAffine()

	return secp256k1.NewPublicKey(&taprootKey.X, &taprootKey.Y)
}

func VerifyTaprootLeafCommitment(controlBlock *ControlBlock,
	taprootWitnessProgram []byte, revealedScript []byte) error {
	rootHash := controlBlock.RootHash(revealedScript)
	taprootKey := ComputeTaprootOutputKey(
		controlBlock.Key, rootHash,
	)
	expectedWitnessProgram := schnorr.SerializePubKey(taprootKey)
	if !bytes.Equal(expectedWitnessProgram, taprootWitnessProgram) {
		return errors.New("")
	}
	derivedYIsOdd := (taprootKey.SerializeCompressed()[0] ==
		secp256k1.PubKeyFormatCompressedOdd)
	if controlBlock.OutputKeyYIsOdd != derivedYIsOdd {
		str := fmt.Sprintf("control block y is odd: %v, derived "+
			"parity is odd: %v", controlBlock.OutputKeyYIsOdd,
			derivedYIsOdd)
		return errors.New(str)
	}
	return nil
}

// For the time being we assume that we do not have any witnessScripts with OpSuccess
func ScriptHasOpSuccess(witnessScript []byte) bool {
    // TODO: implement this
	return false
}

// For the time being we assume that we do not have any witnessScript always parses successfully
func checkScriptParses(witnessScript []byte) bool {
    // TODO: implement this
    return true
}
