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

func SelectTransactionsFromFolder(validTxnsFolderPath string) []*txn.Transaction {
    files, err := os.ReadDir(validTxnsFolderPath)
    if err != nil {
        panic(err)
    }
    txnSlice := make([]*txn.Transaction, 0)

    for _, f := range files {
        var transaction txn.Transaction
        txnPath := fmt.Sprintf("%s/%s", validTxnsFolderPath, f.Name())
        byteResult, _ := os.ReadFile(txnPath)
        err = json.Unmarshal(byteResult, &transaction)
        txnSlice = append(txnSlice, &transaction)
    }
    return txnSlice
}
