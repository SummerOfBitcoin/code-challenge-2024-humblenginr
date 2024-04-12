package txnpicker

import (
	txn "github.com/humblenginr/btc-miner/transaction"
)

type TransactionsPicker struct {
    MempoolDirPath string
    MaxTxWeight int
    MaxTotalWeight int
}

func NewTransactionPicker(mempoolDirPath string, maxTxWeight int, maxTotalWeight int) TransactionsPicker {
    return TransactionsPicker{MempoolDirPath: mempoolDirPath, MaxTxWeight: maxTxWeight, MaxTotalWeight: maxTotalWeight}
}


// PickTransactionsUsingPQ picks valid transactions from the mempool using priority queue. Transaction with higher fee/weight ratio is considered to be high priority. 
func (tp *TransactionsPicker) PickTransactionsUsingPQ() []txn.Transaction {
    q := getTxnsQ(tp.MempoolDirPath)
}

