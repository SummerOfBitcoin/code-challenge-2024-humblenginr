package utils

import (
	"crypto/rand"
	"crypto/sha256"
)

// NewHash returns a new Hash from a byte slice.  An error is returned if
// the number of bytes passed in is not HashSize.
func NewHash(newHash []byte) (*[32]byte) {
	var sh [32]byte
	copy(sh[:], newHash)
	return &sh
}

func DoubleHashRaw(b []byte) [32]byte{
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

func DoubleHash(b []byte) []byte {
    return Hash(Hash(b))
}

func Hash(b []byte) []byte {
    h := sha256.New()
    h.Write(b)
    return h.Sum(nil)
}

func RandomSha256() [32]byte {
    data := make([]byte, 10)
    // assuming that it wont error
    rand.Read(data)
    return sha256.Sum256(data)
}

// TAGGED HASH

var (
	// TagBIP0340Challenge is the BIP-0340 tag for challenges.
	TagBIP0340Challenge = []byte("BIP0340/challenge")

	// TagBIP0340Aux is the BIP-0340 tag for aux data.
	TagBIP0340Aux = []byte("BIP0340/aux")

	// TagBIP0340Nonce is the BIP-0340 tag for nonces.
	TagBIP0340Nonce = []byte("BIP0340/nonce")

	// TagTapSighash is the tag used by BIP 341 to generate the sighash
	// flags.
	TagTapSighash = []byte("TapSighash")

	// TagTagTapLeaf is the message tag prefix used to compute the hash
	// digest of a tapscript leaf.
	TagTapLeaf = []byte("TapLeaf")

	// TagTapBranch is the message tag prefix used to compute the
	// hash digest of two tap leaves into a taproot branch node.
	TagTapBranch = []byte("TapBranch")

	// TagTapTweak is the message tag prefix used to compute the hash tweak
	// used to enable a public key to commit to the taproot branch root
	// for the witness program.
	TagTapTweak = []byte("TapTweak")

	// precomputedTags is a map containing the SHA-256 hash of the BIP-0340
	// tags.
	precomputedTags = map[string]([32]byte){
		string(TagBIP0340Challenge): sha256.Sum256(TagBIP0340Challenge),
		string(TagBIP0340Aux):       sha256.Sum256(TagBIP0340Aux),
		string(TagBIP0340Nonce):     sha256.Sum256(TagBIP0340Nonce),
		string(TagTapSighash):       sha256.Sum256(TagTapSighash),
		string(TagTapLeaf):          sha256.Sum256(TagTapLeaf),
		string(TagTapBranch):        sha256.Sum256(TagTapBranch),
		string(TagTapTweak):         sha256.Sum256(TagTapTweak),
	}
)

// Taken from BIP340 - https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
func TaggedHash(tag []byte, msgs ...[]byte) *[32]byte {
	// Check to see if we've already pre-computed the hash of the tag. If
	// so then this'll save us an extra sha256 hash.
	shaTag, ok := precomputedTags[string(tag)]
	if !ok {
		shaTag = sha256.Sum256(tag)
	}

	// h = sha256(sha256(tag) || sha256(tag) || msg)
	h := sha256.New()
	h.Write(shaTag[:])
	h.Write(shaTag[:])

	for _, msg := range msgs {
		h.Write(msg)
	}

	taggedHash := h.Sum(nil)

	// The function can't error out since the above hash is guaranteed to
	// be 32 bytes.
	hash := NewHash(taggedHash)

	return hash
}
