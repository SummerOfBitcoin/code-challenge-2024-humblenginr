package main

import (
	"encoding/json"
	"fmt"
	"io"
    "bytes"
	"os"

	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
)




func main() {

   fileContent, err := os.Open("../mempool/ff907975dc0cfa299e908e5fba6df56c764866d9a9c22828824c28b8e4511320.json")

   if err != nil {
      panic(err)
   }
   defer fileContent.Close()
   byteResult, _ := io.ReadAll(fileContent)
   var transaction txn.Transaction
    err = json.Unmarshal(byteResult, &transaction)
    if err != nil {
        panic(err)
    }

	w := bytes.NewBuffer(make([]byte, 0, transaction.SerializeSize()))
    err = transaction.Serialize(transaction.HasWitness(), w)
   if err != nil {
      panic(err)
   }
    bytes := w.Bytes()
    txid := utils.DoubleHash(bytes)
    fmt.Printf("Double Hash: %x\n", txid[:])
    fmt.Printf("Tx Hex: %x\n", bytes)
    rev := utils.ReverseBytes(txid)

    fmt.Printf("Reverse: %x\n", utils.Hash(rev))

    ret := txn.ValidateP2PKH(transaction, 0)
    fmt.Printf("Is Valid: %v\n", ret)


}
