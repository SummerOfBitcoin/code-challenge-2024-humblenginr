package mining

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"

	txn "github.com/humblenginr/btc-miner/transaction"
)

// Data types taken from: https://developer.bitcoin.org/reference/block_chain.html
type BlockHeader struct {
    Version int32 `json:"version"`
    PrevBlockHash [32]byte
    MerkleRoot [32]byte
    // Unix timestamp
    Time int64
    // Compact representation of difficulty target
    Bits uint32
    Nonce uint32
}

func (bh *BlockHeader) Serialize(w io.Writer) error {
    buf := make([]byte, 4)

	binary.LittleEndian.PutUint32(buf[:4], uint32(bh.Version))
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	if _, err := w.Write(bh.PrevBlockHash[:]); err != nil {
		return err
	}

	if _, err := w.Write(bh.MerkleRoot[:]); err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(buf[:4], uint32(bh.Time))
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(buf[:4], bh.Bits)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(buf[:4], bh.Nonce)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	return nil
}

func NewBlockHeader(version int32, prevBlockHash [32]byte, merkleRoot [32]byte, time int64, bits uint32, nonce uint32) BlockHeader {
    return BlockHeader{version, prevBlockHash, merkleRoot, time, bits, nonce}
}


type Block struct {
    BlockHeader BlockHeader
    Coinbase txn.Transaction
    Transactions []txn.Transaction
}

func (b *Block) AddTransaction (t txn.Transaction) {
    b.Transactions = append(b.Transactions, t)
}

func (b *Block) WriteToFile(filePath string) error {
    /*
    First line: The block header.
    Second line: The serialized coinbase transaction.
    Following lines: The transaction IDs (txids) of the transactions mined in the block, in order. The first txid should be that of the coinbase transaction
    */
    f, err := os.Create(filePath)
    if err != nil {
        return err
    }
    defer f.Close() 

    w := bufio.NewWriter(f)

    // Block header
    buf := bytes.NewBuffer(make([]byte, 0, 80))
    b.BlockHeader.Serialize(buf)
    w.WriteString(hex.EncodeToString(buf.Bytes())+"\n")

    // Serialized coinbase transaction
    cb := b.Coinbase
    w.WriteString(hex.EncodeToString(cb.RawHex())+"\n")

    // Txid of coinbase transaction
    w.WriteString(hex.EncodeToString(cb.TxHash())+"\n")

    // Txid of rest of the transactions
    for _, txn := range b.Transactions {
        // because the txid of coinbase is already added
        if(txn.Vin[0].IsCoinbase){continue}
        txid := txn.TxHash()
        w.WriteString(hex.EncodeToString(txid)+"\n")
    }
    w.Flush()
    return nil
}

func NewBlock(header BlockHeader, coinbase txn.Transaction, txns []txn.Transaction) Block {
    return Block{header, coinbase, txns}
}

