package mining

import (
	"encoding/hex"
	"math"

	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
)

var MaxVoutIndex uint32 = 0xffffffff
var WitnessReserveHexString = "0000000000000000000000000000000000000000000000000000000000000000"
// in satoshis
var BlockSubsidy int = 0
var CoinbaseTransactionVersion int32 = 1

func NewCoinbaseTransaction(fees int) txn.Transaction {
    var zeroTxid [32]byte
    t := txn.Transaction{}
    t.Version = CoinbaseTransactionVersion

    vin := txn.Vin{}
    vin.IsCoinbase = true
    vin.Txid = hex.EncodeToString(zeroTxid[:])
    vin.Vout = int(MaxVoutIndex)
    // push 3 bytes, 951a06 - which is the block height
    vin.ScriptSig = "03951a06"
    vin.Sequence = math.MaxUint32
    t.Vin = append(t.Vin, vin)

    vout := txn.Vout{}
    // OP_TRUE - anyone can redeem this
    vout.ScriptPubKey = "51"
    vout.Value = BlockSubsidy + fees
    t.Vout = append(t.Vout, vout)

    return t
}

var WitnessMagicBytes = []byte{
		0x6a,
		0x24,
		0xaa,
		0x21,
		0xa9,
		0xed,
	}

func AddWitnessCommitmentX(coinbaseTx *txn.Transaction,
	blockTxns []*txn.Transaction) []byte {

	var witnessNonce [32]byte
	coinbaseTx.Vin[0].Witness = []string{hex.EncodeToString(witnessNonce[:])} 

	// Next, obtain the merkle root of a tree which consists of the
	// wtxid of all transactions in the block. The coinbase
	// transaction will have a special wtxid of all zeroes.
    var zeroHash [32]byte
    wtxids := make([][32]byte, 0)
    for _, t := range blockTxns {
        // coinbase
        if(t.Vin[0].IsCoinbase){
            wtxids = append(wtxids, zeroHash)
        } else {
            wtxids = append(wtxids, [32]byte(utils.ReverseBytes(t.WitnessHash())))
        }
    }

	witnessMerkleRoot := GenerateMerkleTreeRoot(wtxids)

	// The preimage to the witness commitment is:
	// witnessRoot || coinbaseWitness
	var witnessPreimage [64]byte
	copy(witnessPreimage[:32], witnessMerkleRoot[:])
	copy(witnessPreimage[32:], witnessNonce[:])

	// The witness commitment itself is the double-sha256 of the
	// witness preimage generated above. With the commitment
	// generated, the witness script for the output is: OP_RETURN
	// OP_DATA_36 {0xaa21a9ed || witnessCommitment}. The leading
	// prefix is referred to as the "witness magic bytes".
    witnessCommitment := utils.DoubleHash(witnessPreimage[:])
    witnessScript := append(WitnessMagicBytes, witnessCommitment[:]...)

	// Finally, create the OP_RETURN carrying witness commitment
	// output as an additional output within the coinbase.
	commitmentOutput := txn.Vout{
		Value:    0,
		ScriptPubKey: hex.EncodeToString(witnessScript),
	}
	coinbaseTx.Vout = append(coinbaseTx.Vout,
		commitmentOutput)

    return witnessCommitment[:]
}

/*
    What parts are all involved in witness commitment?
    1. Calculation of Merkle root
    2. Witness Commitment = HASH256(witnessMerkleRoot | witnessNonce)
    3. Add (Witness Magic Bytes | Witness commitment) as the ScriptPubKey of the last output in the coinbase transaction

*/
func AddWitnessCommitment(coinbase *txn.Transaction, txns []*txn.Transaction) error {
	var witnessNonce [32]byte

    coinbase.Vin[0].Witness = append(coinbase.Vin[0].Witness, WitnessReserveHexString)
    // assuming that the merkle root is right
	witnessMerkleRoot := CalcMerkleRoot(txns, true)

    var witnessPreimage [64]byte
	copy(witnessPreimage[:32], witnessMerkleRoot[:])
	copy(witnessPreimage[32:], witnessNonce[:])
    witnessCommitment := utils.DoubleHashRaw(witnessPreimage[:])
    witnessCommitment = [32]byte(witnessCommitment[:])
    witnessScript := []byte{
        // OP_RETURN
		0x6a,
        // OP_DATA36
		0x24,
		0xaa,
		0x21,
		0xa9,
		0xed,
	}
    witnessScript = append(witnessScript, witnessCommitment[:]...)
    witnessOut := txn.Vout{}
    witnessOut.Value = 0
    witnessOut.ScriptPubKey = hex.EncodeToString(witnessScript)
    coinbase.Vout = append(coinbase.Vout, witnessOut)

    return nil
}
