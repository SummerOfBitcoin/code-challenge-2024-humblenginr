package mining

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
)

var BlockVersion int32 = 0x00000004
var targetDifficultyHexString = "0000ffff00000000000000000000000000000000000000000000000000000000"

func GetCandidateBlock(txns []*txn.Transaction, hasWitness bool) Block {
	tarDif := new(big.Int)
	tarDif.SetString(targetDifficultyHexString, 16)
    candidateBlock := Block{}

    // header
    header := NewBlockHeader(BlockVersion, utils.RandomSha256(), CalcMerkleRoot(txns, false), time.Now().Unix(),TargetToNbits(tarDif), 0)
    candidateBlock.BlockHeader = header

    // coinbase transaction
    cb := NewCoinbaseTransaction(calculateFees(txns))
    if(hasWitness){
        AddWitnessCommitment(&cb, txns)
    }
    candidateBlock.Coinbase = cb

    // transactions
    for _, t := range txns {
        candidateBlock.AddTransaction(*t)
    }

    return candidateBlock
}

func MineBlock(candidateBlock Block, outputFilePath string) error {
    nonce := findNonce(candidateBlock)
    candidateBlock.BlockHeader.Nonce = nonce
    fmt.Printf("Found nonce: %d", nonce)
    err := candidateBlock.WriteToFile(outputFilePath)
    if err != nil {
        return err
    }
    return nil
}

func findNonce(candidateBlock Block) uint32 {
    // serialized block will be of 80 byte
    w := bytes.NewBuffer(make([]byte, 0, 80))

     
    for {
        nonce := GetRandomNonce()

        header := candidateBlock.BlockHeader
        nBits := candidateBlock.BlockHeader.Bits

        // hash the block header
        // TODO: Properly calculate the capacity
        err := header.Serialize(w)
        if err != nil {
            fmt.Printf("WARN: Could not serialize block header: %v", err)
            // else this might go in infinity loop
            panic(err)
        }
        hash := [32]byte(utils.DoubleHash(w.Bytes()))


        fmt.Printf("Target Value: %d\n", NbitsToTarget(candidateBlock.BlockHeader.Bits))
        fmt.Printf("Hash Value:   %d\n", HashToBig(&hash))

        // compare with difficulty target
        if HashToBig(&hash).Cmp(NbitsToTarget(nBits)) <= 0 {
				return nonce
		}
    }
}

func calculateFees(txns []*txn.Transaction) int {
    fees := 0
    for _, t := range txns {
        fees += t.GetFees()
    }
    return fees
}

func SelectTransactionsFromFolder(validTxnsFolderPath string) []*txn.Transaction {
    // for now we will just select first 15 transactions
    files, err := os.ReadDir(validTxnsFolderPath)
    if err != nil {
        panic(err)
    }
    txnSlice := make([]*txn.Transaction, 0)

    for i, f := range files {
        var transaction txn.Transaction
        if(i == 16) {
            return txnSlice
        }
        txnPath := fmt.Sprintf("%s/%s", validTxnsFolderPath, f.Name())
        byteResult, _ := os.ReadFile(txnPath)
        err = json.Unmarshal(byteResult, &transaction)
        txnSlice = append(txnSlice, &transaction)
    }
    return txnSlice
}
