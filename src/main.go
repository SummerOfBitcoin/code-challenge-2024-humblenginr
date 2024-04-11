package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"

	"container/heap"

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
    validTxnsCount := 0 
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
        if(isValid && !transaction.Vin[0].IsCoinbase){
            fileName := fmt.Sprintf("%s/%s", ValidTxnsDirPath, f.Name())
            os.WriteFile(fileName, byteResult, fs.FileMode(ValidTxnsDirPerm))
            validTxnsCount += 1
        }
        if(validTxnsCount > 3000){
            break
        }
    }
}

func GetValidTxns() PriorityQueue {
    pq := make(PriorityQueue, 0)
    var transaction txn.Transaction
    files, err := os.ReadDir(MempoolDirPath)
    if err != nil {
        panic(err)
    }
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
        if(isValid && !transaction.Vin[0].IsCoinbase){
            priority := int(transaction.GetFeeByWeight() * 100000)
            item := &Item{
                value:    transaction,
                priority: priority,
            }
            heap.Push(&pq, item)
        }
    }
    return pq
}


// An Item is something we manage in a priority queue.
type Item struct {
	value    txn.Transaction // The value of the item; arbitrary.
	priority int    // The priority of the item in the queue.
	// The index is needed by update and is maintained by the heap.Interface methods.
	index int // The index of the item in the heap.
}

// A PriorityQueue implements heap.Interface and holds Items.
type PriorityQueue []*Item

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// We want Pop to give us the highest, not lowest, priority so we use greater than here.
	return pq[i].priority > pq[j].priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*Item)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// update modifies the priority and value of an Item in the queue.
func (pq *PriorityQueue) update(item *Item, value txn.Transaction, priority int) {
	item.value = value
	item.priority = priority
	heap.Fix(pq, item.index)
}

func GetTop2000() []*txn.Transaction{
    pq := GetValidTxns()
    var txns []*txn.Transaction
    for range 2000 {
        item := heap.Pop(&pq).(*Item) 
        txns = append(txns, &item.value)
    }
    return txns
}

func main() {
    UpdateValidTxns()
    txns := GetTop2000()
    candidateBlock := mining.GetCandidateBlock(txns, true)
    mining.MineBlock(candidateBlock, OutputFilePath)
}
