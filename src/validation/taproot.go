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

// NewTapLeaf returns a new TapLeaf with the given leaf version and script to
// be committed to.
func NewTapLeaf(leafVersion TapscriptLeafVersion, script []byte) TapLeaf {
	return TapLeaf{
		LeafVersion: leafVersion,
		Script:      script,
	}
}

// TapHash returns the hash digest of the target taproot script leaf. The
// digest is computed as: h_tapleaf(leafVersion || compactSizeof(script) ||
// script).
func (t TapLeaf) TapHash() [32]byte {
	// The leaf encoding is: leafVersion || compactSizeof(script) ||
	// script, where compactSizeof returns the compact size needed to
	// encode the value.
	var leafEncoding bytes.Buffer
	_ = leafEncoding.WriteByte(byte(t.LeafVersion))
	_ = transaction.WriteVarBytes(&leafEncoding, t.Script)

	return *utils.TaggedHash(utils.TagTapLeaf, leafEncoding.Bytes())
}

// tapBranchHash takes the raw tap hashes of the right and left nodes and
// hashes them into a branch. See The TapBranch method for the specifics.
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
    // Public key in the taproot commitment
	Key *secp256k1.PublicKey

	// OutputKeyYIsOdd denotes if the y coordinate of the output key (the
	// key placed in the actual taproot output is odd.
	OutputKeyYIsOdd bool

	// LeafVersion is the specified leaf version of the tapscript leaf that
	// the InclusionProof below is based off of.
	LeafVersion TapscriptLeafVersion

	// InclusionProof is a series of merkle branches that when hashed
	// pairwise, starting with the revealed script, will yield the taproot
	// commitment root.
	InclusionProof []byte
}

var ControlBlockMaxSize = 33 + 32 + 128



// ParseControlBlock attempts to parse the raw bytes of a control block. An
// error is returned if the control block isn't well formed, or can't be
// parsed.
func ParseControlBlock(ctrlBlock []byte) (*ControlBlock, error) {
	// The control block minimally must contain 33 bytes (for the leaf
	// version and internal key) along with at least a single value
	// comprising the merkle proof. If not, then it's invalid.
	switch {
	// The control block must minimally have 33 bytes for the internal
	// public key and script leaf version.
	case len(ctrlBlock) < 33:
		str := fmt.Sprintf("min size is %v bytes, control block "+
			"is %v bytes", 33, len(ctrlBlock))
		return nil, errors.New(str)

	// The control block can't be larger than a proof for the largest
	// possible tapscript merkle tree with 2^128 leaves.
	case len(ctrlBlock) > ControlBlockMaxSize:
		str := fmt.Sprintf("max size is %v, control block is %v bytes",
			ControlBlockMaxSize, len(ctrlBlock))
		return nil, errors.New(str)

	// Ignoring the fixed sized portion, we expect the total number of
	// remaining bytes to be a multiple of the node size, which is 32
	// bytes.
	case (len(ctrlBlock)-33)%32 != 0:
		str := fmt.Sprintf("control block proof is not a multiple "+
			"of 32: %v", len(ctrlBlock)-33)
		return nil, errors.New(str)
	}

	leafVersion := TapscriptLeafVersion(ctrlBlock[0] & 0xfe)

	// Extract the parity of the y coordinate of the internal key.
	var yIsOdd bool
	if ctrlBlock[0]&0x01 == 0x01 {
		yIsOdd = true
	}

	// Next, we'll parse the public key, which is the 32 bytes following
	// the leaf version.
	rawKey := ctrlBlock[1:33]
	pubKey, err := schnorr.ParsePubKey(rawKey)
	if err != nil {
		return nil, err
	}

	// The rest of the bytes are the control block itself, which encodes a
	// merkle proof of inclusion.
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
	// We'll start by creating a new tapleaf from the revealed script,
	// this'll serve as the initial hash we'll use to incrementally
	// reconstruct the merkle root using the control block elements.
	merkleAccumulator := NewTapLeaf(c.LeafVersion, revealedScript).TapHash()

	// Now that we have our initial hash, we'll parse the control block one
	// node at a time to build up our merkle accumulator into the taproot
	// commitment.
	//
	// The control block is a series of nodes that serve as an inclusion
	// proof as we can start hashing with our leaf, with each internal
	// branch, until we reach the root.
	numNodes := len(c.InclusionProof) / 32
	for nodeOffset := 0; nodeOffset < numNodes; nodeOffset++ {
		// Extract the new node using our index to serve as a 32-byte
		// offset.
		leafOffset := 32 * nodeOffset
		nextNode := c.InclusionProof[leafOffset : leafOffset+32]

		merkleAccumulator = tapBranchHash(merkleAccumulator[:], nextNode)
	}

	return merkleAccumulator[:]
}

// ComputeTaprootOutputKey calculates a top-level taproot output key given an
// internal key, and tapscript merkle root. The final key is derived as:
// taprootKey = internalKey + (h_tapTweak(internalKey || merkleRoot)*G).
func ComputeTaprootOutputKey(pubKey *secp256k1.PublicKey,
	scriptRoot []byte) *secp256k1.PublicKey {

	// This routine only operates on x-only public keys where the public
	// key always has an even y coordinate, so we'll re-parse it as such.
	internalKey, _ := schnorr.ParsePubKey(schnorr.SerializePubKey(pubKey))

	// First, we'll compute the tap tweak hash that commits to the internal
	// key and the merkle script root.
	tapTweakHash := utils.TaggedHash(
		utils.TagTapTweak, schnorr.SerializePubKey(internalKey),
		scriptRoot,
	)

	// With the tap tweak computed,  we'll need to convert the merkle root
	// into something in the domain we can manipulate: a scalar value mod
	// N.
	var tweakScalar secp256k1.ModNScalar
	tweakScalar.SetBytes((*[32]byte)(tapTweakHash))

	// Next, we'll need to convert the internal key to jacobian coordinates
	// as the routines we need only operate on this type.
	var internalPoint secp256k1.JacobianPoint
	internalKey.AsJacobian(&internalPoint)

	// With our intermediate data obtained, we'll now compute:
	//
	// taprootKey = internalPoint + (tapTweak*G).
	var tPoint, taprootKey secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&tweakScalar, &tPoint)
	secp256k1.AddNonConst(&internalPoint, &tPoint, &taprootKey)

	// Finally, we'll convert the key back to affine coordinates so we can
	// return the format of public key we usually use.
	taprootKey.ToAffine()

	return secp256k1.NewPublicKey(&taprootKey.X, &taprootKey.Y)
}

// VerifyTaprootLeafCommitment attempts to verify a taproot commitment of the
// revealed script within the taprootWitnessProgram (a schnorr public key)
// given the required information included in the control block. An error is
// returned if the reconstructed taproot commitment (a function of the merkle
// root and the internal key) doesn't match the passed witness program.
func VerifyTaprootLeafCommitment(controlBlock *ControlBlock,
	taprootWitnessProgram []byte, revealedScript []byte) error {
	// First, we'll calculate the root hash from the given proof and
	// revealed script.
	rootHash := controlBlock.RootHash(revealedScript)
	// Next, we'll construct the final commitment (creating the external or
	// taproot output key) as a function of this commitment and the
	// included internal key: taprootKey = internalKey + (tPoint*G).
	taprootKey := ComputeTaprootOutputKey(
		controlBlock.Key, rootHash,
	)
	// If we convert the taproot key to a witness program (we just need to
	// serialize the public key), then it should exactly match the witness
	// program passed in.
	expectedWitnessProgram := schnorr.SerializePubKey(taprootKey)
	if !bytes.Equal(expectedWitnessProgram, taprootWitnessProgram) {
		return errors.New("")
	}
	// Finally, we'll verify that the parity of the y coordinate of the
	// public key we've derived matches the control block.
	derivedYIsOdd := (taprootKey.SerializeCompressed()[0] ==
		secp256k1.PubKeyFormatCompressedOdd)
	if controlBlock.OutputKeyYIsOdd != derivedYIsOdd {
		str := fmt.Sprintf("control block y is odd: %v, derived "+
			"parity is odd: %v", controlBlock.OutputKeyYIsOdd,
			derivedYIsOdd)
		return errors.New(str)
	}
	// Otherwise, if we reach here, the commitment opening is valid and
	// execution can continue.
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
