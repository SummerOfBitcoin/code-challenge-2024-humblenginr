package txnpicker

import (
	txn "github.com/humblenginr/btc-miner/transaction"
)

type TransactionsPicker struct {
    MempoolDirPath string
    MaxTxWeight int
    MaxTotalWeight int
    MaxFees int
}

func NewTransactionPicker(mempoolDirPath string, maxTxWeight int, maxTotalWeight int, maxFees int) TransactionsPicker {
    return TransactionsPicker{MempoolDirPath: mempoolDirPath, MaxTxWeight: maxTxWeight, MaxTotalWeight: maxTotalWeight, MaxFees: maxFees}
}



// PickTransactionsUsingPQ picks valid transactions from the mempool using priority queue. Transaction with higher fee/weight ratio is considered to be high priority. 
func (tp *TransactionsPicker) PickUsingPQ() []*txn.Transaction {
    q := getTxnsQ(tp.MempoolDirPath)
    txns := make([]*txn.Transaction, 0)
    totalWeight := 0
    totalFee := 0

    item := q.Pop(); 
    for item != nil {
        tx := txn.Transaction(item.(Item))
        weight := tx.GetWeight()
        fee := tx.GetFees()
        if((weight+ totalWeight < tp.MaxTotalWeight) && (fee + totalFee < tp.MaxFees)) {
            txns = append(txns, &tx)
            totalWeight += weight
            totalFee += fee

        }
        item = q.Pop()
    }
    return txns
}

