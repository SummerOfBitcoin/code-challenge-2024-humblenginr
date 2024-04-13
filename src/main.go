package main

import (
	"fmt"

	"github.com/humblenginr/btc-miner/mining"
	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
	"github.com/humblenginr/btc-miner/txnpicker"
)


var (
    OutputFilePath = "../output.txt"
    MempoolDirPath = "../mempool"
    MaxTxWeight = 4000000
    BlockHeaderWeight = 320
    MaxTotalWeight = 4000000 - BlockHeaderWeight

)

func LogDetailsAboutTx(tx txn.Transaction){
    txid := tx.TxHash()
     rev := utils.ReverseBytes(txid)
     fmt.Printf("Tx hex: %x\n",tx.RawHex() )
     fmt.Printf("Txid: %x\n", txid)
     fmt.Printf("Filename: %x\n", utils.Hash(rev))
}

func main() {
    picker := txnpicker.NewTransactionPicker(MempoolDirPath, MaxTxWeight, MaxTotalWeight)
    txns := picker.PickUsingPQ()
    candidateBlock := mining.GetCandidateBlock(txns, true)
    mining.MineBlock(candidateBlock, OutputFilePath)
}
