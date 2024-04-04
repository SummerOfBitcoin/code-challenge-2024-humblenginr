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
    // p2pkh
   fileContent, err := os.Open("../mempool/ff907975dc0cfa299e908e5fba6df56c764866d9a9c22828824c28b8e4511320.json")
    // p2wpkh
    fileContent, err = os.Open("../mempool/ff9c6d05b875c29adb975d4d3c80977bc2f8371be90b71a185da90127ffd37f3.json")
    fileContent, err = os.Open("../mempool/feb678eaf0f8326c6f34e47953afe7244eac7a1ebe7e55ebdb6bf1ccb0d2aaae.json")
    fileContent, err = os.Open("../mempool/ff45041e1dacbe980606470f65a3d2b454347d28415cae0d87915126f17bfdd2.json")
    // p2wpkh
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
    txid := transaction.TxHash()
    rev := utils.ReverseBytes(txid)
    fmt.Printf("Filename should be: %x\n", utils.Hash(rev))
    ret := transaction.Validate(0)
    fmt.Printf("Is Valid: %v\n", ret)
}
