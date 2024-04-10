package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"

	"github.com/humblenginr/btc-miner/mining"
	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
	"github.com/humblenginr/btc-miner/validation"
)

var (
    MempoolDirPath = "../mempool"
    ValidTxnsDirPath = "../valid-txns"
    OutputFilePath = "../output.txt"
    ValidTxnsDirPerm = 0755
)

func Validate(tx txn.Transaction) bool {
    for inputIdx := range tx.Vin {
        if(!validation.Validate(tx, inputIdx)){
            return false
        }
    } 
    return true
}

func LogDetailsAboutTx(tx txn.Transaction){
     txid := tx.TxHash()
     rev := utils.ReverseBytes(txid)
     fmt.Printf("Tx hex: %x\n",tx.RawHex() )
     fmt.Printf("Txid: %x\n", txid)
     fmt.Printf("Filename: %x\n", utils.Hash(rev))
}

func UpdateValidTxns() {
    os.RemoveAll(ValidTxnsDirPath)
    files, err := os.ReadDir(MempoolDirPath)
    if err != nil {
        panic(err)
    }
    var transaction txn.Transaction
    for _, f := range files {
        txnPath := fmt.Sprintf("%s/%s", MempoolDirPath, f.Name())
        byteResult, _ := os.ReadFile(txnPath)
        err = json.Unmarshal(byteResult, &transaction)
        if err != nil {
            panic(err)
        }
        isValid := Validate(transaction)
        err = os.MkdirAll(ValidTxnsDirPath, fs.FileMode(ValidTxnsDirPerm))
        if err != nil {
            panic(err)
        }
        if(isValid){
            fileName := fmt.Sprintf("%s/%s", ValidTxnsDirPath, f.Name())
            os.WriteFile(fileName, byteResult, fs.FileMode(ValidTxnsDirPerm))
        }
    }
}

func main() {
    // UpdateValidTxns()
    txns := mining.SelectTransactionsFromFolder(ValidTxnsDirPath)
    candidateBlock := mining.GetCandidateBlock(txns, true)
    mining.MineBlock(candidateBlock, OutputFilePath)
}
