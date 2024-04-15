package validation
import (
	"encoding/hex"
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
    default:
        return false
    }
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

// there are two paths for validating taproot transactions:
// 1. Key spending
// 2. Script spending
// With key spending, there is only one value in the witness, and we consider that as the signature
// With script spending, it is different
/*
 For keypath spending, the sighash should not include 

 So, I think this is what we have to do. First we have a witness array. First we look at how many elements are in the witness array. If there is only one element in the array, then we can do the normal key path spending with the only element in the witness array as the signature.
If there are more than one elements in the witness array, then we have to do the following (let w be the witness array):
    pre: if len(w) != 3, then log this tx and return because we don't yet know how to handle this.
    1. Find if the annex is there remove it from the w(witness array)
    2. Let c be the control block, which is w[len(w)-1] and parse it
    3. Let s be the witness script, which is w[len(w)-2]
    4. Let p be the public key taken from the prevout scriptpubkey push_32
    6. Validate the taprootLeafCommitment with c,s and p (return false if not)
    (from BIP342)
    7. Check if the witness script has any success opcodes, if yes, then return true
    8. Now we ensure that s parses successfully (we do this here because BIP342 says that the validation succeeds with OP_SUCCESS in s even if other bytes of s fails to decode)
    After this, the actual implementation differs from what we are doing. As per the actual specification, we have to execute the witnessScript(s), but we are going to assume that all the scripts are going to be in one form and just check the signature.
    9. We verify that the script is in the expected form (<PUSH_32 pk <CHECK_SIG> <OP_0><OP_IF> ... <OP_ENDIF>)
    9. Let pk = s[2:?] be the public key
    10. Let sig be the first element in the witness array
    11. Now finally verify the sig with pk
*/
func validateP2TR( tx transaction.Transaction, trIdx int ) bool {
    txIn := tx.Vin[trIdx]
    witness := txIn.Witness
    sighashes := sighash.TaprootSigHashes{
        HashPrevoutsV1: [32]byte(tx.CalcHashPrevOuts()[:]),
        HashSequenceV1: [32]byte(tx.CalcHashSequence()[:]),
        HashOutputsV1: [32]byte(tx.CalcHashOutputs()[:]),
        HashInputAmountsV1: [32]byte(tx.CalcHashInputAmounts()[:]),
        HashInputScriptsV1: [32]byte(tx.CalcHashInputScripts()[:]),
    }
    annex, _ := ExtractAnnex(tx.Vin[trIdx].Witness)
    var annexBytes []byte
    if annex != "" {
            annexBytes,_ = hex.DecodeString(annex)
    }

    if(len(witness) == 1){
        // Key path spending
        pubkey, _ := hex.DecodeString(txIn.PrevOut.ScriptPubKey[4:])
        sigBytes, _ := hex.DecodeString(txIn.Witness[0])
        // 1. Parse public key and signature
        pk, sig, hashtype, err :=  schnorr.ParseSigAndPubkey(pubkey, sigBytes)
        if err != nil {
            // fmt.Println("Cannot parse signatuer and pub key: "+ err.Error())
            return false
        }
        // 2. Calculate signature hash
        sighash, err := sighash.CalcTaprootSignatureHash(&sighashes, hashtype,&tx, trIdx, nil, annexBytes)
        if err != nil {
            // fmt.Println("Cannot calculate signature hash : "+ err.Error())
            return false
        }
        // 3. Verify signature
        serializedPubkey := schnorr.SerializePubKey(pk)
        return schnorr.Verify(sig, sighash, serializedPubkey)
    } else {
        // script path spending
        if(len(witness) != 3){
            // fmt.Printf("WARN: Rejecting unknown transaction. We don't yet know how to validate this transaction input: %s\n", txIn)
            return false
        }
        s,_ := hex.DecodeString(witness[len(witness)-2])
        if(s[33] != 0xac) {
            // fmt.Printf("Witness script: %x\n", s)
            // fmt.Printf("WARN: Skipping the transaction input since it's witness script is unrecognisable: %s\n", txIn)
            return false
        }
        // remove annex from the witness array, if found
        witness,_ = RemoveAnnexFromWitness(witness)
        // fmt.Printf("INFO: Witness length: %d\n", len(witness))
        // parse the control block
        cb_bytes,_ := hex.DecodeString(witness[len(witness)-1])
        c, err := ParseControlBlock(cb_bytes)
        // verify taproot leaf commitment
        q, _ := hex.DecodeString(txIn.PrevOut.ScriptPubKey[4:])
        err = VerifyTaprootLeafCommitment(c,q,s)
        if err != nil {
            return false
        }
        if(ScriptHasOpSuccess(s)) {
            return true
        }
        // parse the witness script
         if(!checkScriptParses(s)){
            return false
        }
        // parse sig and pk
        sigBytes, _ := hex.DecodeString(witness[0])
        pk, sig, hashtype, err :=  schnorr.ParseSigAndPubkey(s[1:33], sigBytes)
        if err != nil {
            return false
        }
        // calculate sighash
        tapLeafHash := NewTapLeaf(0xc0,s).TapHash()
        // fmt.Printf("p: %x, q: %x, k: %x\n",cb_bytes[1:33],q, utils.ReverseBytes(tapLeafHash[:]))

        sighash, err := sighash.CalcTaprootSignatureHash(&sighashes, hashtype,&tx, trIdx,utils.ReverseBytes(tapLeafHash[:]), annexBytes)
        if err != nil {
        }
        // fmt.Printf("Schnorr Sighash: %x\n", sighash)
        serializedPubkey := schnorr.SerializePubKey(pk)
        return schnorr.Verify(sig, sighash, serializedPubkey)
    }
}

func validateP2WPKH( tx transaction.Transaction, trIdx int ) bool {
    txIn := tx.Vin[trIdx]
    pubkey, _ := hex.DecodeString(txIn.Witness[1])
    sigBytes, _ := hex.DecodeString(txIn.Witness[0])
    // 1. Parse public key and signature
    pk, sig, hashtype, err :=  ecdsa.ParseSigAndPubkey(pubkey, sigBytes)
    if err != nil {
        panic("Cannot parse signature and pub key: "+ err.Error())
        }
    subscript := txIn.PrevOut.ScriptPubKey
    subscriptBytes, _ := hex.DecodeString(subscript)
    // 2. Calculate signature hash
    // for v0 segwit, we use double hash, whereas for v1 segwit (taproot), we just use single hash 
    cache := sighash.SegwitSigHashes{HashPrevouts: [32]byte(utils.Hash(tx.CalcHashPrevOuts()[:])), HashSequence: [32]byte(utils.Hash(tx.CalcHashSequence()[:])), HashOutputs: [32]byte(utils.Hash(tx.CalcHashOutputs()[:]))}
    sighash, err := sighash.CalcWitnessSignatureHash(subscriptBytes, &cache, hashtype,&tx, trIdx)
    if err != nil {
        panic("Cannot calculate signature hash : "+ err.Error())
    }
    // 3. Verify signature
    return ecdsa.Verify(sig, sighash, pk)
}
