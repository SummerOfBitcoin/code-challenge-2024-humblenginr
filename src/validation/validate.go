package validation

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/humblenginr/btc-miner/utils"
	"github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/validation/ecdsa"
	"github.com/humblenginr/btc-miner/validation/sighash"
	"github.com/humblenginr/btc-miner/validation/schnorr"
)


func Validate( tx transaction.Transaction , trIdx int) bool {
    // Get transaction type
    i := tx.Vin[trIdx]
    // 1. Verify pubkey_asm
    // 2. Verify pubkey_addr
    // 3. Sum of Inputs <= Sum of Outputs
    if(tx.GetFees() < 0){
        return false
    }
    // 4. Verify signature
    scriptType := i.GetScriptType()
    switch scriptType {
    case transaction.P2PKH:
       return validateP2PKH(tx, trIdx) 
    case transaction.P2WPKH:
       return validateP2WPKH(tx, trIdx) 
    case transaction.P2TR:
       return validateP2TR(tx, trIdx) 
    }
    return true
} 

func validateP2PKH(tx transaction.Transaction, trIdx int) bool {
    scriptSigInstrs := strings.Split(tx.Vin[trIdx].ScriptSigAsm, " ")
    pubkey, _ := hex.DecodeString(scriptSigInstrs[len(scriptSigInstrs)-1])
    sigBytes, _ := hex.DecodeString(scriptSigInstrs[1])
    // 1. Parse public key and signature
    pk, sig,hashtype, err :=  ecdsa.ParseSigAndPubkey(pubkey, sigBytes)
    if err != nil {
        panic("Cannot parse signatuer and pub key: "+ err.Error())
    }
    subscript := tx.Vin[trIdx].PrevOut.ScriptPubKey
    subscriptBytes, _ := hex.DecodeString(subscript)
    // 2. Calculate signature hash
    sighash := sighash.CalcSignatureHash(subscriptBytes, hashtype, &tx, trIdx)
    // 3. Verify signature
    return ecdsa.Verify(sig, sighash, pk)
}

func validateP2TR( tx transaction.Transaction, trIdx int ) bool {

    txIn := tx.Vin[trIdx]
    pubkey, _ := hex.DecodeString(txIn.PrevOut.ScriptPubKey[4:])
    sigBytes, _ := hex.DecodeString(txIn.Witness[0])
    // 1. Parse public key and signature
    pk, sig, hashtype, err :=  schnorr.ParseSigAndPubkey(pubkey, sigBytes)
    if err != nil {
        panic("Cannot parse signatuer and pub key: "+ err.Error())
    }
    // 2. Calculate signature hash
    annex, _ := ExtractAnnex(tx.Vin[trIdx].Witness)
    var opts []sighash.TaprootSigHashOption
	if annex != "" {
        annexBytes,_ := hex.DecodeString(annex)
		opts = append(opts, sighash.WithAnnex(annexBytes))
	}

    sighashes := sighash.TaprootSigHashes{
        HashPrevoutsV1: [32]byte(tx.CalcHashPrevOuts()[:]),
        HashSequenceV1: [32]byte(tx.CalcHashSequence()[:]),
        HashOutputsV1: [32]byte(tx.CalcHashOutputs()[:]),
        HashInputAmountsV1: [32]byte(tx.CalcHashInputAmounts()[:]),
        HashInputScriptsV1: [32]byte(tx.CalcHashInputScripts()[:]),
    }
    sighash, err := sighash.CalcTaprootSignatureHash(&sighashes, hashtype,&tx, trIdx)
    if err != nil {
        panic("Cannot calculate signature hash : "+ err.Error())
    }
    // 3. Verify signature
    serializedPubkey := schnorr.SerializePubKey(pk)
    return schnorr.Verify(sig, sighash, serializedPubkey)
}

func validateP2WPKH( tx transaction.Transaction, trIdx int ) bool {
    txIn := tx.Vin[trIdx]
    pubkey, _ := hex.DecodeString(txIn.Witness[1])
    sigBytes, _ := hex.DecodeString(txIn.Witness[0])
    // 1. Parse public key and signature
    pk, sig, hashtype, err :=  ecdsa.ParseSigAndPubkey(pubkey, sigBytes)
    if err != nil {
        panic("Cannot parse signatuer and pub key: "+ err.Error())
        }
    subscript := txIn.PrevOut.ScriptPubKey
    subscriptBytes, _ := hex.DecodeString(subscript)
    // 2. Calculate signature hash
    // for v0 segwit, we use double hash, whereas for v1 segwit (taproot), we just use single hash 
    cache := sighash.SegwitSigHashes{HashPrevouts: [32]byte(utils.Hash(tx.CalcHashPrevOuts()[:])), HashSequence: [32]byte(utils.Hash(tx.CalcHashSequence()[:])), HashOutputs: [32]byte(utils.Hash(tx.CalcHashOutputs()[:]))}
    fmt.Println("Hashtype: ", hashtype)
    sighash, err := sighash.CalcWitnessSignatureHash(subscriptBytes, &cache, hashtype,&tx, trIdx)
    if err != nil {
        panic("Cannot calculate signature hash : "+ err.Error())
    }
    // 3. Verify signature
    return ecdsa.Verify(sig, sighash, pk)
}
