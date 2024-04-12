package txnpicker

import (
	"encoding/json"
	"fmt"
	"os"

	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/validation"
	"github.com/x1m3/priorityQueue"
)

var (
    MempoolDirPath = "../mempool"
)

type Item txn.Transaction

func (i Item) HigherPriorityThan(other priorityQueue.Interface) bool {
	return i.Priority > other.(Item).Priority
}

func validateHelper(tx txn.Transaction) bool {
    for inputIdx := range tx.Vin {
        if(!validation.Validate(tx, inputIdx)){
            return false
        }
    } 
    return true
}

// GetTxnsQ returns a priority queue of valid transactions. It uses the mempoolDirPath as the folder to look for transactions. 
func getTxnsQ(mempoolDirPath string) *priorityQueue.Queue {
    pq := priorityQueue.New()
    files, err := os.ReadDir(MempoolDirPath)
    if err != nil {
        panic(err)
    }
    for _, f := range files {
        var transaction txn.Transaction
        txnPath := fmt.Sprintf("%s/%s", MempoolDirPath, f.Name())
        byteResult, _ := os.ReadFile(txnPath)
        err = json.Unmarshal(byteResult, &transaction)
        if err != nil {
            panic(err)
        }
        isValid := validateHelper(transaction)
        if(isValid && !transaction.Vin[0].IsCoinbase){
            transaction.UpdatePriority()
            pq.Push(Item(transaction))
        }
    }
    return pq
}
