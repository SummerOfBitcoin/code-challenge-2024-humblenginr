package transaction

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/humblenginr/btc-miner/utils"
	//"github.com/humblenginr/btc-miner/validation"
)

type ScriptPubKeyType string

const (
	P2PKH ScriptPubKeyType = "p2pkh"
	P2SH ScriptPubKeyType = "p2sh"
	P2WPKH ScriptPubKeyType = "v0_p2wpkh"
	P2WSH ScriptPubKeyType = "v0_p2wsh"
	P2TR ScriptPubKeyType = "v1_p2tr"
)

type Vout struct {
    // Assumption: ScriptPubKey is the hex encoded string of the binary representation of ScriptPubKeyAsm
    ScriptPubKey string `json:"scriptpubkey"`
    ScriptPubKeyAsm string `json:"scriptpubkey_asm"`
    ScriptPubKeyType ScriptPubKeyType `json:"scriptpubkey_type"`
    ScriptPubKeyAddr string `json:"scriptpubkey_address"`
    Value int `json:"value"`
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (o *Vout) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of ScriptPubKey +
	// ScriptPubKey bytes.
    pubkeyscript,err := hex.DecodeString(o.ScriptPubKey)
    if err != nil {
        panic("Error while serializing Vin: " + err.Error())
    }


	return 8 + VarIntSerializeSize(uint64(len(pubkeyscript))) + len(pubkeyscript)
}

func (v Vout) String() string {
    return fmt.Sprintf("(scriptpubkey: %s, scriptpubkeyasm: %s, scriptpubkeytype: %s, scriptppubkeyaddr: %s, value: %d)", v.ScriptPubKey, v.ScriptPubKeyAsm, v.ScriptPubKeyType, v.ScriptPubKeyAddr, v.Value )
}


type Vin struct {
    Txid string `json:"txid"`
    // this is the index of the output
    Vout int `json:"vout"`
    PrevOut Vout `json:"prevout"`
    ScriptSig string `json:"scriptsig"`
    ScriptSigAsm string `json:"scriptsig_asm"`
    Witness []string `json:"witness"`
    IsCoinbase bool `json:"is_coinbase"`
    Sequence int `json:"sequence"`
}



// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
func (i *Vin) SerializeSize() int {
	// Txid 32 bytes + Vout 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of ScriptSig +
	// SignatureScript bytes.

    // Assuming that the transaction is non-segwit
    sigscript,err := hex.DecodeString(i.ScriptSig)
    if err != nil {
        panic("Error while serializing Vin: " + err.Error())
    }
	return 40 + VarIntSerializeSize(uint64(len(sigscript))) +
		len(sigscript)
}

func (v Vin) String() string {
    return fmt.Sprintf("(txid: %s, vout: %d, prevout: %s, scriptsig: %s, scriptsigasm: %s, witness: %v, iscoinbase: %v, sequence: %d)",v.Txid, v.Vout, v.PrevOut, v.ScriptSig, v.ScriptSigAsm, v.Witness, v.IsCoinbase, v.Sequence )
}

type Transaction struct {
    Version int32 `json:"version"`
    Locktime uint32 `json:"locktime"`
    Vin []Vin `json:"vin"`
    Vout []Vout `json:"vout"`
}


func (tx *Transaction) ShallowCopy() Transaction {
	txCopy := Transaction{
		Version:  tx.Version,
		Vin:     make([]Vin, len(tx.Vin)),
		Vout:    make([]Vout, len(tx.Vout)),
		Locktime: tx.Locktime,
	}
	txIns := make([]Vin, len(tx.Vin))
	for i, oldTxIn := range tx.Vin {
		txIns[i] = oldTxIn
		txCopy.Vin[i] = txIns[i]
	}
	txOuts := make([]Vout, len(tx.Vout))
	for i, oldTxOut := range tx.Vout {
		txOuts[i] = oldTxOut
		txCopy.Vout[i] = txOuts[i]
	}
	return txCopy
}

func (t *Transaction) HasWitness() bool {
	for _, txIn := range t.Vin {
		if len(txIn.Witness) != 0 {
			return true
		}
	}
	return false
}


func (tx *Transaction) SerializeSizeWithWitness() int {
    witnessSize := 0
    for _, t := range tx.Vin {
        witnessByteArray := make([][]byte, 0)
        for _, w := range t.Witness{
            witness,_ := hex.DecodeString(w)
            witnessByteArray = append(witnessByteArray, witness)
        }
        witnessSize += SerializeWitnessSize(witnessByteArray)
    }
    return tx.SerializeSize() + witnessSize
}

// SerializeSize returns the serialized size of the transaction without accounting for any witness data.
func (tx *Transaction) SerializeSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(tx.Vin))) +
		VarIntSerializeSize(uint64(len(tx.Vout)))

	for _, txIn := range tx.Vin {
		n += txIn.SerializeSize()
	}

	for _, txOut := range tx.Vout {
		n += txOut.SerializeSize()
	}

	if tx.HasWitness() {
		// The marker, and flag fields take up two additional bytes.
		n += 2

		// Additionally, factor in the serialized size of each of the
		// witnesses for each txin.
		for _, txin := range tx.Vin {
            witness := make([][]byte, 0)
            for _, wString := range txin.Witness{
                wBytes, _ := hex.DecodeString(wString)
                witness = append(witness, wBytes)
            }
			n += SerializeWitnessSize(witness)
		}
	}
	return n
}

func (t Transaction) GetFees() int {
    // transaction fees = input sum value - output sum value
    inputSum, outputSum := 0,0
    for _,input := range t.Vin {
        inputSum += input.PrevOut.Value
    }
    for _,output := range t.Vout {
        outputSum += output.Value
    }

    return inputSum - outputSum
}

func (t Transaction) String() string {
    return fmt.Sprintf("Version: %d \nLocktime: %d \nVin: %s \nVout: %s", t.Version , t.Locktime, t.Vin, t.Vout)
}


// RawHex gives the serialized transaction with witness data if any in bytes
func (t Transaction) RawHex() []byte {
   w := bytes.NewBuffer(make([]byte, 0, t.SerializeSize()))
   err := t.Serialize(true, w)
   if err != nil {
      panic(err)
   }
    bytes := w.Bytes()
    return bytes
}

func (t Transaction) TxHash() []byte {
    w := bytes.NewBuffer(make([]byte, 0, t.SerializeSize()))
    // For calculating txid, we don't need the witness data
    err := t.Serialize(false, w)
   if err != nil {
      panic(err)
   }
    bytes := w.Bytes()
    txhash := utils.DoubleHash(bytes)
    return txhash
}

func (t Transaction) WitnessHash() []byte {
    w := bytes.NewBuffer(make([]byte, 0, t.SerializeSize()))
    // For calculating txid, we don't need the witness data
    err := t.Serialize(true, w)
   if err != nil {
      panic(err)
   }
    bytes := w.Bytes()
    txhash := utils.DoubleHash(bytes)
    return txhash
}

func (input Vin) GetScriptType() ScriptPubKeyType {
    return input.PrevOut.ScriptPubKeyType
}

