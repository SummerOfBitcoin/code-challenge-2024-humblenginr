package mining

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	txn "github.com/humblenginr/btc-miner/transaction"
	"github.com/humblenginr/btc-miner/utils"
)

var BlockVersion int32 = 0x00000004
var targetDifficultyHexString = "0000ffff00000000000000000000000000000000000000000000000000000000"
var prevBlockHash = "1cc89d151ecc14e3c323fd538f8259c3e6a5ecfeb467395f651de50818a50000"

func findValidPrevBlockHash(nBits uint32) [32]byte {
    for {
        hash := utils.RandomSha256()
        if HashToBig(&hash).Cmp(NbitsToTarget(nBits)) <= 0 {
				return hash
		}

    }
}



var MaxBlockWeight = 4000000 - 1000 // 1000 is the buffer amount

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
    nBits := TargetToNbits(tarDif)
    prevBH,_ := hex.DecodeString(prevBlockHash)
    txids := make([][32]byte, 0)
    for _, t := range blockTxns {
        txids = append(txids, [32]byte(utils.ReverseBytes(t.TxHash())))
    }
    header := NewBlockHeader(BlockVersion, *utils.NewHash(prevBH), GenerateMerkleTreeRoot(txids), time.Now().Unix(),nBits, 0)
    candidateBlock.BlockHeader = header

    // transactions
    for _, t := range blockTxns {
        candidateBlock.AddTransaction(*t)
    }

    return candidateBlock
}

func MineBlock(candidateBlock Block, outputFilePath string) error {
    findNonce(&candidateBlock)
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
            // else this might go in infinity loop
            panic(err)
        }

        hash := utils.DoubleHashRaw(w.Bytes())

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


