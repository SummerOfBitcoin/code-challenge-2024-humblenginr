package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/validation"
	"github.com/humblenginr/btc-miner/utils"
)


func main() {
    // p2pkh
   fileContent, err := os.Open("../mempool/ff907975dc0cfa299e908e5fba6df56c764866d9a9c22828824c28b8e4511320.json")
    // p2wpkh
    fileContent, err = os.Open("../mempool/ff9c6d05b875c29adb975d4d3c80977bc2f8371be90b71a185da90127ffd37f3.json")
    fileContent, err = os.Open("../mempool/feb678eaf0f8326c6f34e47953afe7244eac7a1ebe7e55ebdb6bf1ccb0d2aaae.json")
    fileContent, err = os.Open("../mempool/ff45041e1dacbe980606470f65a3d2b454347d28415cae0d87915126f17bfdd2.json")
    // p2tr - key path spending
    fileContent, err = os.Open("../mempool/00d9c01fd8722f63cc327c93e59de64395d1e6ca5861ae6b9b149b364d082352.json")
    fileContent, err = os.Open("../mempool/02e09abed1c49fa18819425c9fde49b3dcfcc9a2652fee7c8c3e15fd7f140fa3.json")
    // p2tr - script path spending
     fileContent, err = os.Open("../mempool/feb1fe7a84a3f56e2f1b761855b20082a012d55c50f4d5fcbfc9478ad8fcb9fe.json")
     fileContent, err = os.Open("../mempool/faa72f786352755f8cf783f03b062c48c13f35b22b67acb658dfaeb12ecd189f.json")
     fileContent, err = os.Open("../mempool/fd72b15b25fd18f95bcf35aab35f2b51056f4b39cb79f2bae06551c7e6951430.json")
     fileContent, err = os.Open("../mempool/fac725231f08430c92a0542d39932aa91a26d857386bfb12cbb49899d753f3a9.json")

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
    fmt.Printf("Tx hex: %x\n",transaction.RawHex() )
    fmt.Printf("Txid should be: %x\n", txid)
    fmt.Printf("Filename should be: %x\n", utils.Hash(rev))
    ret := validation.Validate(transaction, 0)
    fmt.Printf("Is Valid: %v\n", ret)
}
