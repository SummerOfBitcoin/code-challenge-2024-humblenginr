package mining

import (
	"encoding/hex"

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
    t.Locktime = 0

    vin := txn.Vin{}
    vin.IsCoinbase = true
    vin.Txid = hex.EncodeToString(zeroTxid[:])
    vin.Vout = int(MaxVoutIndex)
    // push 3 bytes, 951a06 - which is the block height
    vin.ScriptSig = "03951a06"
    vin.ScriptSigAsm = "PUSH_3 951a06"
    vin.Sequence = 0
    t.Vin = append(t.Vin, vin)

    vout := txn.Vout{}
    // OP_TRUE - anyone can redeem this
    vout.ScriptPubKey = "51"
    vout.ScriptPubKeyAsm = "OP_TRUE"
    vout.Value = BlockSubsidy + fees
    t.Vout = append(t.Vout, vout)

    return t
}

func AddWitnessCommitment(coinbase *txn.Transaction, txns []*txn.Transaction) error {
	var witnessNonce [32]byte

    coinbase.Vin[0].Witness = append(coinbase.Vin[0].Witness, WitnessReserveHexString)
	witnessMerkleRoot := CalcMerkleRoot(txns, true)

    var witnessPreimage [64]byte
	copy(witnessPreimage[:32], witnessMerkleRoot[:])
	copy(witnessPreimage[32:], witnessNonce[:])
    witnessCommitment := utils.DoubleHashRaw(witnessPreimage[:])
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
