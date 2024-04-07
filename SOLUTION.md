# Mining Simulation of a Bitcoin Block 

## Brainstorming 

So basically we have to do the following things:
1. Validate the transactions and assign fee/size to each one of them and order them 
    1. Write a parser that parses the transactions and puts them in a data strucutre that I can make use of
    2. Write a minimal Script interpreter
2. Create and serialize the coinbase transaction
3. Mine the block 
    1. Create the candidate block header (which is just the file)
    2. Add the txids by using the ordered fee/size list
    3. Find the nonce by iteratively hashing the file with difference nonces

Programming language to use: Golang

## Transaction verification

### Parsing a transaction

- [x] Parse a transaction into a data structure

### Validation

There are different types of transactions:
1. p2pkh (pay to public key hash)
2. p2sh (pay to script hash)
3. p2wpkh (pay to script hash)
4. p2wsh (pay to witness script hash)
5. p2tr

What about multisigs?
First we will only take these things into account. If a transaction any other type than this, then we will log it and see what it is.

Previous output is included in the transaction itself.
**Rules** 

Sourced from [verify.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/consensus/tx_verify.cpp), 
[transactions.html](https://developer.bitcoin.org/devguide/transactions.html)

1. Check all the inputs are present and valid (we don't have to check this)
2. Check for negative or overflow input values
3. Tally transaction fees (it should not be negative)
4. Script validation
*We will assume that all the inputs are valid UTXOs, if prevout is not given, then that means we are making use of a transaction in the given list

To validate a transaction, first we have to check if all the inputs are valid, and then we have to tally the transaction fees, then we have to identify what kind of script 
it is, and then validate it accordingly. Let us first just validate the P2PKH 

### Writing an interpreter for Script
Do we really need to write an interpreter for the Script language?
No. We don't need to write an interpreter for the Script, we just have to programmatically validate the script and signature

### Serialization
We can use this resource https://learnmeabitcoin.com/technical/transaction/. I had one problem though. Eventhough I did everything right, I was not able to match my txid hash with 
my filename. After looking at it, the issue was that I had to _reverse the transaction hash order in the transaction inputs_. My reasoning towards why we need to do this is because, in Bitcoin, the convention is to use the Natural Byte Order (little endian) when dealing within raw bitcoin data, whereas we use Reverse Byte Order (Big Endian) in Block explorers or RPC calls to bitcoin-core. In our case, the transactions are in JSON form, which means the transaction hash would be in Reverse Byte Order. But the specification in https://learnmeabitcoin.com/technical/transaction/ says that the transaction hash in the input should be in Natural Byte Order. Therefore I had to reverse it in order to get it working. 

### Verifying Signature
How do we verify the signature. We basically have to do what the OP_CHECKSIG opcode does in the Script language.
We need the Signature, the public key and the transaction hash in order to verify the signature. We have to verify the signature 
using the ECDSA algorithm.We cannot use any bitcoin related libraries.  
Out of the required things, we have the Signature and the public key. We need to identify how to calculate the transaction hash.
Following things have to be done:
1. Identify how to correctly serialize the transactions in bitcoin
2. Identify the right library to use for ECDSA verification

I think [this](https://learn.saylor.org/mod/book/view.php?id=36340&chapterid=18915#:~:text=Hints%3A,bytes%2C%20or%208b%20in%20hex) is how we 
need to seralize a transaction. 

https://btcinformation.org/en/developer-reference#raw-transaction-format - serialization for non-segwit transactions
https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki - serialization for segiwit transactions

When we serialize it and double hash it using SHA256, we have to get the transaction ID. This is how we can verify that the serialization is right.
So what we need for verifying the signature is a single SHA256 hash of the serialized transaction.

What is this DER encoding with signatures?

The process of verification consists of the following steps: (taken from https://wiki.bitcoinsv.io/index.php/OP_CHECKSIG#:~:text=OP_CHECKSIG%20is%20an%20opcode%20that,signature%20check%20passes%20or%20fails.)
1. Check that the signature is encoded in the correct format - <DER Sgignature><Hashtyype>
2. Check that the public key is encoded in the correct format - both compressed and uncompressed are accepted
3. We serialize the transaction bytes using 'sighash' based on the sighash type - https://wiki.bitcoinsv.io/index.php/OP_CHECKSIG#:~:text=OP_CHECKSIG%20is%20an%20opcode%20that,signature%20check%20passes%20or%20fails.


### Validation Rules
What are the validations we have to perform is an important question to ask.
INPUT:
1. Verify pubkey address
2. Verify pubkey_asm with pubkeyscript(?)
3. Verify signature

4. Verify (sum of outputs <= sum of inputs)

We will start with these validations, and run the tests, and then based on the results we can add more rules.


### Assigning fee/size 
Here we basically have to calculate the transaction fees for the given transaction, and then store them in a map that has transaction
id as the key and the (fee/size) as the value.


## Coinbase transaction

## Mining a block
