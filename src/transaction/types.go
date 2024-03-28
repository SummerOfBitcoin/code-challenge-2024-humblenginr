package transaction

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/humblenginr/btc-miner/utils"
)

type ScriptPubKeyType string

const (
	P2PKH ScriptPubKeyType = "p2pkh"
	P2SH ScriptPubKeyType = "p2sh"
	P2WPKH ScriptPubKeyType = "v0_p2wpkh"
	P2WSH ScriptPubKeyType = "v0_p2wsh"
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

// SerializeSize returns the serialized size of the transaction without accounting
// for any witness data.
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

	return n
}

func serializeAndWriteTxOutput(w io.Writer, to Vout) error {
    // value
    buffer := make([]byte, 8)
    binary.LittleEndian.PutUint64(buffer,uint64(to.Value))
    w.Write(buffer)
    // pubkey script
    pubkeyScript, err := hex.DecodeString(to.ScriptPubKey)
    if(err != nil){
        return err
    }
    err = WriteVarBytes(w, pubkeyScript)
	if err != nil {
		return err
	}
    return nil
}




func serializeAndWriteTxInput(w io.Writer, ti Vin) error {
    // reference output transaction id
    txid, err := hex.DecodeString(ti.Txid)
    // has to be in Natural Byte Order (little endian)
    // since the transaction is in JSON form, I think the convention is to reverse the 
    // transaction hash order when sending over the wire, and hence we have to reverse it back so that we can work with it
    txid = utils.ReverseBytes(txid)
    if(err != nil){
        return err
    }
    w.Write(txid[:])
    // reference output transaction index
    buffer := make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer,uint32(ti.Vout))
    w.Write(buffer)
    // signature script
    sigScript, err := hex.DecodeString(ti.ScriptSig)
    if(err != nil){
        return err
    }
    err = WriteVarBytes(w, sigScript)
	if err != nil {
		return err
	}
    // sequence number
    buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer,uint32(ti.Sequence))
    w.Write(buffer)
    return nil
}



// Should serialize the transaction according 
// to https://wiki.bitcoinsv.io/index.php/OP_CHECKSIG#:~:text=OP_CHECKSIG%20is%20an%20opcode%20that,signature%20check%20passes%20or%20fails.
// If it is a segwit transaction, then we have to use https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
// I am also currently referencing the implementation from btcd golang repository - https://github.com/btcsuite/btcd
func (t *Transaction) Serialize(doWitness bool, w io.Writer) ( error) {
    // nVersion
    buffer := make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer,uint32(t.Version))
    w.Write(buffer)
    // witness
    if doWitness {
		if _, err := w.Write([]byte{0x00, 0x01}); err != nil {
			return err
		}
	}
    // input count
	count := uint64(len(t.Vin))
    err := WriteVarInt(w, count)
	if err != nil {
		return err
	}
    // serialize all the transaction inputs
    for _, ti := range t.Vin {
		err = serializeAndWriteTxInput(w, ti)
		if err != nil {
			return err
		}
	}
    // output count
	count = uint64(len(t.Vout))
    err = WriteVarInt(w, count)
	if err != nil {
		return  err
	}
    // serialize all the transaction outputs
    for _, to := range t.Vout {
		err = serializeAndWriteTxOutput(w, to)
		if err != nil {
			return  err
		}
	}
    // witness
    if doWitness {
		for _, ti := range t.Vin {
            witness := make([][]byte, 0)
            for _, w := range ti.Witness {
                byteArray, err := hex.DecodeString(w)
                if err != nil {
                    panic("Error while decoding witness: "+ err.Error())
                }
                witness = append(witness, byteArray)
            }
			err = writeTxWitness(w, t.Version, witness)
			if err != nil {
				return  err
			}
		}
	}
    // locktime
    buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer,uint32(t.Locktime))
    w.Write(buffer)
    return nil
}

func writeTxWitness(w io.Writer, version int32, wit [][]byte) error {
	err := WriteVarInt(w, uint64(len(wit)))
	if err != nil {
		return err
	}
	for _, item := range wit {
		err = WriteVarBytes(w, item)
		if err != nil {
			return err
		}
	}
	return nil
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

func (input Vin) GetScriptType() ScriptPubKeyType {
    return input.PrevOut.ScriptPubKeyType
}

