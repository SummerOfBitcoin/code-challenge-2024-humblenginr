package transaction

import (
	"encoding/hex"
	"fmt"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/humblenginr/btc-miner/utils"
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


// TODO: Have to validate the public key hash first
func ValidateP2PKH(tx Transaction, trIdx int) bool {
    scriptSigInstrs := strings.Split(tx.Vin[trIdx].ScriptSigAsm, " ")
    pubkey, _ := hex.DecodeString(scriptSigInstrs[len(scriptSigInstrs)-1])
    sigBytes, _ := hex.DecodeString(scriptSigInstrs[1])
    // 1. Parse public key and signature
    pk, sig,hashtype, err :=  parseSigAndPubkey(pubkey, sigBytes)
    if err != nil {
        panic("Cannot parse signatuer and pub key: "+ err.Error())
    }
    subscript := tx.Vin[trIdx].PrevOut.ScriptPubKey
    subscriptBytes, _ := hex.DecodeString(subscript)
    // 2. Calculate signature hash
    sighash := calcSignatureHash(subscriptBytes, hashtype, &tx, trIdx)
    // 3. Verify signature
    return Verify(sig, sighash, pk)
}

// TODO: Have to validate the public key hash first
func ValidateP2WPKH( tx Transaction, trIdx int ) bool {
    txIn := tx.Vin[trIdx]
    pubkey, _ := hex.DecodeString(txIn.Witness[1])
    sigBytes, _ := hex.DecodeString(txIn.Witness[0])
    // 1. Parse public key and signature
    pk, sig, hashtype, err :=  parseSigAndPubkey(pubkey, sigBytes)
    if err != nil {
        panic("Cannot parse signatuer and pub key: "+ err.Error())
    }
    subscript := txIn.PrevOut.ScriptPubKey
    subscriptBytes, _ := hex.DecodeString(subscript)
    // 2. Calculate signature hash
    // for v0 segwit, we use double hash, whereas for v1 segwit (taproot), we just use single hash 
    cache := SegwitSigHashes{HashPrevouts: [32]byte(utils.Hash(tx.calcHashPrevOuts()[:])), HashSequence: [32]byte(utils.Hash(tx.calcHashSequence()[:])), HashOutputs: [32]byte(utils.Hash(tx.calcHashOutputs()[:]))}
    fmt.Println("Hashtype: ", hashtype)
    sighash, err := calcWitnessSignatureHash(subscriptBytes, &cache, hashtype,&tx, trIdx)
    if err != nil {
        panic("Cannot calculate signature hash : "+ err.Error())
    }
    // 3. Verify signature
    return Verify(sig, sighash, pk)
}
