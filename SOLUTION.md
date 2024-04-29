# Mining Simulation of a Bitcoin Block 

## Design Approach
Our approach to designing the block construction program involves several key concepts aimed at creating a valid Bitcoin block:

### 1. Validating and Selecting Transactions
We first validate transactions by ensuring the correctness of various attributes such as pubkey, address, input/output sums, and signature scripts. We focus on implementing signature validations for P2PKH, P2WPKH, and P2TR scripts. Transactions are then selected based on their fee/weight ratio to optimize block space usage.

### 2. Creating a Candidate Block
Once validated transactions are selected, we construct a candidate block with a valid coinbase transaction. This includes generating the coinbase transaction structure and adding the witness commitment if witness data is present. Additionally, we construct the block header with appropriate values such as bits, prevBlockHash, merkle root, time, and blockversion.

### 3. Mining the Block
After creating the candidate block, we search for a nonce that satisfies the current difficulty target. This process involves iteratively changing the nonce value, hashing the block header, and checking if the resulting hash meets the difficulty criteria.

## Implementation Details

### Validation

#### Validating P2PKH Scripts
```pseudo
For each P2PKH transaction:
    Parse public key and signature.
    Verify hash type encoding.
    Parse public key using the `secp` package.
    Ensure signature is in proper DER format and parse it.
    Calculate signature hash (SIGHASH).
    Verify signature using ECDSA algorithm.
```

#### Validating P2WPKH Scripts
```pseudo
For each P2WPKH transaction:
    Parse signature and public key from witness array.
    Calculate signature hash (SIGHASH) using BIP143.
    Verify signature using ECDSA algorithm.
```

#### Validating P2TR Scripts
```pseudo
For each P2TR transaction:
    If len(witness array) == 1:
        Perform key path spending with single element in the witness array as signature.
    Else if len(witness array) > 1:
        If len(witness array) != 3:
            Log this transaction and return.
        Remove annex if present from witness array.
        Parse control block, witness script, and public key.
        Validate taprootLeafCommitment.
        Check for success opcodes in witness script.
        Ensure witness script parses successfully.
        Verify signature with public key.
```

### Picking Transactions
Valid transactions are added to a priority queue based on their fee/weight ratio. Transaction weight is calculated considering both the serialized size and the size of witness bytes.

### Creating a Candidate Block
After selecting transactions, we create the coinbase transaction and add the witness commitment if required. We then construct the block header with appropriate values and add the transactions to the candidate block.

#### Witness Commitment
```pseudo
Create array of transaction hashes for all transactions (zero hash for coinbase).
Generate merkle tree root for array of transaction hashes.
Calculate witness commitment as double hash of concatenated 64-byte array of witness merkle root and witness nonce.
Add output entry to coinbase transaction with witness script as witness commitment.
```

### Finding the Nonce
```pseudo
While block hash is not below difficulty target:
    Generate random nonce.
    Set nonce value in block header.
    Hash block header.
```

## Results and Performance

### Validation Performance
- Successfully validated 7377 out of 8130 transactions, covering P2PKH, P2WPKH, and P2TR script types.

### Transaction Selection
- Prioritized transactions based on fee/weight ratio, optimizing block space usage. There is room for further improvement here like taking weighted average etc.

### Block Creation
- Successfully created coinbase transaction and witness commitment, ensuring integrity and security of the block's data.

#### Witness Commitment
- Witness commitment added to the coinbase transaction, ensuring integrity and security of the block's witness data.

### Mining Performance
- Efficiently discovered nonce within the difficulty target, demonstrating robustness of mining algorithm.
- Average mining time per block: Y seconds.

## Conclusion
Our Bitcoin block mining simulation effectively demonstrates key functionalities of the Bitcoin network. By validating transactions, selecting them based on their fee/weight ratio, and constructing valid blocks, we've illustrated the process of creating a secure and efficient blockchain. The mining algorithm efficiently discovers nonces meeting the required difficulty target, highlighting the resilience of the Bitcoin protocol. Future research could focus on further optimizing transaction selection algorithms and exploring advancements in mining efficiency.

## References
- Bitcoin Developer Documentation: [https://developer.bitcoin.org/](https://developer.bitcoin.org/)
- Bitcoin Improvement Proposals (BIPs): [https://bitcoin.org/en/development#bips](https://bitcoin.org/en/development#bips)
- Decred's secp package: [https://github.com/decred/dcrd/dcrec/secp256k1/v4](https://github.com/decred/dcrd/dcrec/secp256k1/v4)
- Bitcoin SV Wiki for OP_CHECKSIG: [https://wiki.bitcoinsv.io/index.php/OP_CHECKSIG#:~:text=OP_CHECKSIG%20is%20an%20opcode%20that,signature%20check%20passes%20or%20fails](https://wiki.bitcoinsv.io/index.php/OP_CHECKSIG#:~:text=OP_CHECKSIG%20is%20an%20opcode%20that,signature%20check%20passes%20or%20fails)
- Bitcoin Improvement Proposals (BIP) 143
