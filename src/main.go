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
        if(isValid){
            fileName := fmt.Sprintf("%s/%s", ValidTxnsDirPath, f.Name())
            os.WriteFile(fileName, byteResult, fs.FileMode(ValidTxnsDirPerm))
            validTxnsCount += 1
        }
        if(validTxnsCount > 20){
            break
        }
    }
}

var TemporaryValidTxn =  []string{
    "000cb561188c762c81f76976f816829424e2af9e0e491c617b7bf41038df3d35.json",
}

var TemporaryValidTxns =  []string{
    "000cb561188c762c81f76976f816829424e2af9e0e491c617b7bf41038df3d35.json",
    "001035505afbf143e51bd667099190943a38eee20092bb691e72eaa44992b2f7.json",
    "0018c221bca3da35128baabe412a14c95b6864b2e6f7f7a8ffdd8eb0923dec49.json",
    "001e296ba3feddda174e62df57506861823b0831af983364d2c1808779b443f7.json", 
    "0022a52ad27796a1a2d9eddd6f4b055c097b51ad7cb8f000fe0d78b26cb71639.json",
    "002f5ff2f870154b109d823bbad6fd349582d5b85ead5ce0f9f7a4a0270ce37a.json",
    "0030b203ff93ff7f4c6fdabda1026a8167038dfb94985669721086df9ad4337a.json",
    "00359dc6a7cf0d808eb5cf6450cf8243408395c6fa5be649f4f6c3b5a394d1b7.json",
    "003d95255dacb65b0896ab1fc7d3f88d347c762d5164de45a5bea75da95c3830.json",
    "004c2dec582638c26fed3d55b2fee8bbf1c2d4b70449b0a3f03faa105ad03f15.json",
    "00550d2c315129f77a97d1b5f8483d1efc9e9edebbb229dcf4a87e0c988f6840.json",
    "005747a8401a6ef30f3d55172fea54a4c4e940d0dcde372087aea286661e04c5.json",
    "00703f54c52da70ce7a94f2f59b73c2435476eb531362adb20e78ecc159dd376.json",
    "007b0fd78cdb709f83823b79fd9824bc39873632c6472f4e4d7c766f9a7e0e82.json",
    "00b6d3b2d204a97a8877e34c1f3ce454cba5d299aab705e263b49328cbc683f1.json",
    "00b8ffa99b973547fb665bdee70d3123f345c12664046e767777a822284fea3f.json",
    "00c4387b3de5d0376b3df4db81a6016b584aad10c5aff619d15627e43ca4d697.json",
    "00cd2a7549860949e9b7b1c182060ace476f5127f3ee561d72633ffaaea2b2ec.json",
    "00d12b523d8b7ad90e2269767478764c243625539dc59bcd457d14ca1aa4e38c.json",
    "00d7c8ddc2e75f6ba97520623390f01a910dc66a9e6a2052ee31f1b99aabdea5.json",
    "00d9c01fd8722f63cc327c93e59de64395d1e6ca5861ae6b9b149b364d082352.json",
}


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

// Block Hash does not meet difficulty target

func main() {
    UpdateValidTxns()
    txns := SelectTransactionsFromPaths(TemporaryValidTxns)
    candidateBlock := mining.GetCandidateBlock(txns, true)
    mining.MineBlock(candidateBlock, OutputFilePath)
}
