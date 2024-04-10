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
    fmt.Sscanf(targetDifficultyHexString, "%064x", tarDif)
    candidateBlock := Block{}
    
    var blockTxns []*txn.Transaction

    // coinbase transaction
    cb := NewCoinbaseTransaction(calculateFees(txns))
    blockTxns = append(blockTxns, &cb)
    for _, t := range txns {
        blockTxns = append(blockTxns, t)
    }

    if(hasWitness){
        AddWitnessCommitment(&cb, blockTxns)
    }
    candidateBlock.Coinbase = cb

    // header
    header := NewBlockHeader(BlockVersion, utils.RandomSha256(), CalcMerkleRoot(blockTxns, false), time.Now().Unix(),TargetToNbits(tarDif), 0)
    candidateBlock.BlockHeader = header

    // transactions
    for _, t := range blockTxns {
        candidateBlock.AddTransaction(*t)
    }

    return candidateBlock
}

func MineBlock(candidateBlock Block, outputFilePath string) error {
    nonce := findNonce(&candidateBlock)
    fmt.Printf("Found nonce: %d", nonce)
    err := candidateBlock.WriteToFile(outputFilePath)
    if err != nil {
        return err
    }
    return nil
}

func findNonce(candidateBlock *Block) uint32 {
    // serialized block will be of 80 byte
    for {
        w := bytes.NewBuffer(make([]byte, 0, 84))
        nonce := GetRandomNonce()
        candidateBlock.BlockHeader.Nonce = nonce

        header := candidateBlock.BlockHeader
        nBits := candidateBlock.BlockHeader.Bits

        // hash the block header
        err := header.Serialize(w)
        if err != nil {
            fmt.Printf("WARN: Could not serialize block header: %v", err)
            // else this might go in infinity loop
            panic(err)
        }

        hash := utils.DoubleHashRaw(w.Bytes())

        fmt.Printf("Hash:   %x\n", hash)
        fmt.Printf("Hash Value:   %d\n", HashToBig(&hash))
        // fmt.Printf("Target Value: %d\n", NbitsToTarget(candidateBlock.BlockHeader.Bits))

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
