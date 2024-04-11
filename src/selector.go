package main

import (
	"encoding/json"
	"fmt"
	"os"

	txn "github.com/humblenginr/btc-miner/transaction"
)



func SelectTransactionsFromPaths(validTxnPaths []string) []*txn.Transaction {
    txnSlice := make([]*txn.Transaction, 0)

    for _, fileName := range validTxnPaths {
        var transaction txn.Transaction
        txnPath := fmt.Sprintf("%s/%s", MempoolDirPath, fileName)
        byteResult, _ := os.ReadFile(txnPath)
        json.Unmarshal(byteResult, &transaction)
        txnSlice = append(txnSlice, &transaction)
    }
    return txnSlice
}


