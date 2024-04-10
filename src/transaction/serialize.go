package transaction

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
    "fmt"

	"github.com/humblenginr/btc-miner/utils"
)

func SerializeWitnessSize(witness [][]byte) int {
	// A varint to signal the number of elements the witness has.
	n := VarIntSerializeSize(uint64(len(witness)))

	// For each element in the witness, we'll need a varint to signal the
	// size of the element, then finally the number of bytes the element
	// itself comprises.
	for _, witItem := range witness {
		n += VarIntSerializeSize(uint64(len(witItem)))
		n += len(witItem)
	}
	return n
}


func (tx *Transaction) CalcHashInputAmounts() []byte {
	var b bytes.Buffer
	for _, txIn := range tx.Vin {
		prevOut := txIn.PrevOut
        err := binary.Write(&b, binary.LittleEndian, uint64(prevOut.Value))
        if err != nil {
            fmt.Println(err)
        }
	}
    return utils.Hash(b.Bytes()[:])
}

func (tx *Transaction) CalcHashInputScripts() []byte {
	var b bytes.Buffer
	for _, txIn := range tx.Vin {
		prevOut := txIn.PrevOut

        scriptPubKey,_ := hex.DecodeString(prevOut.ScriptPubKey)
		_ = WriteVarBytes(&b, scriptPubKey)
	}
    return utils.Hash(b.Bytes()[:])
}


func (tx *Transaction) CalcHashPrevOuts() []byte {
	var b bytes.Buffer
	for _, in := range tx.Vin {
        prevOutHash,_ := hex.DecodeString(in.Txid)
        // transaction hash has to be reversed when used internally
        prevOutHash = utils.ReverseBytes(prevOutHash)
		b.Write(prevOutHash[:])

		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(in.Vout))
		b.Write(buf[:])
	}

    return utils.Hash(b.Bytes()[:])
}
func (tx *Transaction) CalcHashSequence() []byte {
	var b bytes.Buffer
	for _, in := range tx.Vin {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(in.Sequence))
		b.Write(buf[:])
	}

    return utils.Hash(b.Bytes()[:])
}

func (tx *Transaction) CalcHashOutputs() []byte {
	var b bytes.Buffer
	for _, out := range tx.Vout {
        SerializeAndWriteTxOutput(&b, out)
	}
    return utils.Hash(b.Bytes()[:])
}



func SerializeAndWriteTxOutput(w io.Writer, to Vout) error {
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

// Serialize the transaction according 
// to https://wiki.bitcoinsv.io/index.php/OP_CHECKSIG#:~:text=OP_CHECKSIG%20is%20an%20opcode%20that,signature%20check%20passes%20or%20fails.
// I am also currently referencing the implementation from btcd golang repository - https://github.com/btcsuite/btcd
// doWitness - whether or not witness information should be included
func (t *Transaction) Serialize(includeWitness bool, w io.Writer) ( error) {
    // nVersion
    buffer := make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer,uint32(t.Version))
    w.Write(buffer)
    // witness
    if includeWitness {
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
		err = SerializeAndWriteTxOutput(w, to)
		if err != nil {
			return  err
		}
	}
    if includeWitness {
		for _, ti := range t.Vin {
            witness := make([][]byte, 0)
            for _, w := range ti.Witness {
                byteArray, err := hex.DecodeString(w)
                if err != nil {
                    panic("Error while decoding witness: "+ err.Error())
                }
                witness = append(witness, byteArray)
            }
			err = writeTxWitness(w, witness)
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

func writeTxWitness(w io.Writer, wit [][]byte) error {
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
