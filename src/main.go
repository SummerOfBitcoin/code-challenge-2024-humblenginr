package main

import (
	"fmt"

	"github.com/humblenginr/btc-miner/mining"
	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
)


var OutputFilePath = "../output.txt"




func LogDetailsAboutTx(tx txn.Transaction){
    txid := tx.TxHash()
     rev := utils.ReverseBytes(txid)
     fmt.Printf("Tx hex: %x\n",tx.RawHex() )
     fmt.Printf("Txid: %x\n", txid)
     fmt.Printf("Filename: %x\n", utils.Hash(rev))
}

func main() {
    pq := GetTxnsQ()
    candidateBlock := mining.GetCandidateBlock(pq, true)
    mining.MineBlock(candidateBlock, OutputFilePath)
}
