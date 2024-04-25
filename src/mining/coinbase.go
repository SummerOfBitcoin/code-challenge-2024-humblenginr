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

var PreWitnessScriptBytes = []byte{
		0x6a,
		0x24,
		0xaa,
		0x21,
		0xa9,
		0xed,
	}

func AddWitnessCommitment(coinbaseTx *txn.Transaction,
	blockTxns []*txn.Transaction) []byte {
	var witnessNonce [32]byte
	coinbaseTx.Vin[0].Witness = []string{hex.EncodeToString(witnessNonce[:])} 

    var zeroHash [32]byte
    wtxids := make([][32]byte, 0)
    for _, t := range blockTxns {
        // coinbase
        if(t.Vin[0].IsCoinbase){
            wtxids = append(wtxids, zeroHash)
        } else if(t.HasWitness()) {
            wtxids = append(wtxids, [32]byte(utils.ReverseBytes(t.WitnessHash())))
        } else {
            wtxids = append(wtxids, [32]byte(utils.ReverseBytes(t.TxHash())))
        }
    }

	witnessMerkleRoot := GenerateMerkleTreeRoot(wtxids)

	var witnessPreimage [64]byte
	copy(witnessPreimage[:32], witnessMerkleRoot[:])
	copy(witnessPreimage[32:], witnessNonce[:])

    witnessCommitment := utils.DoubleHash(witnessPreimage[:])
    witnessScript := append(PreWitnessScriptBytes, witnessCommitment[:]...)

	commitmentOutput := txn.Vout{
		Value:    0,
		ScriptPubKey: hex.EncodeToString(witnessScript),
	}
	coinbaseTx.Vout = append(coinbaseTx.Vout,
		commitmentOutput)

    return witnessCommitment[:]
}
