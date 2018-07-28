# On proof-of-cooperation
by Thomas König, tom@pylon-network.org, 0x21792bf5

## Motivation
Two years ago I became aware of the enormous demand for energy and the concentration of power around some pool operators in the Bitcoin network.  I thought that there must be a better way to do it.  Why not try to let nodes cooperate instead of competing to generate blocks.  In many thought experiments I tried to eliminate mining and replace it with something different that serves the same purpose.  A profound assumption of the new system is that cooperation is more efficient than competition.  The concept of proof-of-cooperation was born and I started work on the white paper[1].

## Overview
Proof-of-cooperation (in short PoC) is implemented in Pyloncoin[2], which is a fork of the Bitcoin 0.12 branch.  All mining related code has been removed and replaced by PoC code.  Block generation is performed by so-called Cooperatively Validated Nodes (CVNs).  CVNs are appointed in a democratic process which is out of the scope of this technical document.  CVNs can be added or removed from the network dynamically.  CVN information is stored in the blockchain.  The mandatory transaction fees go to the respective block creators to compensate their efforts for running a CVN.  Certain chain parameters, e.g. the time between blocks, the amount of the transaction fee, etc. are dynamically adjustable without the need of releasing a new wallet version.  These dynamic chain parameters are also stored in the blockchain.  The appointed Pyloncoin blockchain administrators (not the developers) take on the task of managing these parameters.  The Pyloncoin network is comprised of a virtually unlimited number of full nodes and a limited number of CVNs.  The maximum hard coded value is 100 but the actual target is 40-50 CVNs.

## The 3 major building blocks
1. The logic to find out which CVN ID (unsigned 32bit) should create the next
   block in a deterministic way by examining the blockchain history.
2. All CVNs achieve consensus about this CVN ID by signing a piece of data
   comprised of the hash of the last chain tip and the CVN ID of the next block
   creator.
3. Create the blocks and incorporate transactions, the proof data, and optional
   additional chain data into it.

### Who's next
We start searching backwards through the chain to find out which CVN has created its last block the furthest in the past.  Once we've identified that node ID, we make sure that it was recently actively collaborating in the network by checking for the signatures of that node in the last couple of blocks.  If the node was active, it will be chosen as the next block creator - the next CVN ID.  Although this might sound like a simple round robin system complexity is introduced by handling exceptional cases.  E.g. a CVN could go offline at any time, or a split-brain situation could occur in the network, etc...

The main logic for determining the next block creator can be found in the function CheckNextBlockCreator() in src/poc.cpp.


### Decide together
After examining the blockchain history all CVNs broadcast their vote about who should create the next block by signing the hashed concatenation of the last blockhash and the CVN ID.  We use an EC-Schnorr multi signature algorithm for best efficiency.  Every CVN creates a partial signature which it then sends to the network.  These partial signatures are validated and relayed by every node. When a CVN creates a block it combines all these signatures into one and incorporates this combined signature into the new block along with information about which CVNs co-signed.  Finally, the block creator signs the resulting blockhash with a standard EC-Schnorr signature to prove that it was the creator.  This block signature also goes into the block.

### The block factory
Like miners in the Bitcoin network CVNs create the blocks in the Pyloncoin network.  In contrast to Bitcoin the block hash has no special meaning and does not have any special property like starting with a certain amount of zero bits.   When the target block spacing time is up the CVN that was determined in the consensus process creates the block by storing pending transactions and the multisignature of all CVNs (the actual proof of cooperation) in the block.  It then signs the blockhash.  The resulting signature is also added to the block.

## Code overview
Most of the core PoC logic is located in the file src/poc.cpp.  The classes of most of the PoC related functionality are defined in src/primitives/cvn.h.  Blocks are created in src/blockfactory.cpp (derived from miner.cpp).

### The PoC thread
The PoC thread is started in src/poc.cpp by the function POCThread().  This thread implements a state machine that handles the different states between two blocks.  The state is kept in the class POCStateHolder.

### Fasito (Pyloncoin signature token)
This is a hardware device which contains the non-retrievable private key and is able to create EC-Schnorr partial signatures that form the PoC proof.  It is based on the Teensy3.2 USB development board[3] which features a 32 bit ARM processor and memory protection.  Our firmware is open source and available on Github[4].

### EC-Schnorr signing
The private key is generated on the Fasito hardware device (see below) and is non-retrievable.  This is mostly for two reasons:
* First, to prevent accidentally or maliciously starting more than one CVN with the same credentials which would interfere with the network.
* Second, to prevent key cancellation attacks.

The EC-Schnorr multi-signature system is processed in 3 phases:

1. All CVNs use a random nonce pair, exchange the public part to every other CVN, and keep the private part secret on the Fasito.

2. All CVNs combine the public nonce of all other CVNs and create their partial signature for the current chain tip.

3. The agreed block creator combines all partial signatures into one and puts it into the block.

#### 1st Phase: The nonce exchange
Because this multi-step signature system is rather complex and has to happen in the time between the creation of two blocks, and also requires CVNs to send numerous messages back and forth they pre-compute a number of nonce pairs into a nonce pool and share that with all other CVNs. This decouples the first phase from this time-sensitive process and thus makes it more robust.  Every nonce pool is associated with a chain tip and one nonce is used up per block height.  If the pool is empty a new one is created and sent.  This is done right after a new tip has been received.  The implementation can be found in CreateNewNoncePool() in src/poc.cpp.

#### 2nd Phase: The partial signature
By using the nonce pool CVNs can create their partial signature right away after they have received a new block and don't have to wait for the public nonces to arrive.  They first combine the public nonces of all other nodes for a given height and then use this sum of nonces and their private key to sign the following hash.

`hash = H( hashPrevBlock || nNextCreator )`

I extended libsecp256k1[5] to be able to validate partial EC-Schnorr signatures.  This is done in CvnVerifyPartialSignature() in poc.cpp.

#### 3rd Phase: Combining the signatures
The block creator validates and combines all the received partial signatures into **one** 64 byte EC-Schnorr signature which is verifiable against the signed hash and the sum of all public keys of the participating CVNs.  This makes PoC validation very efficient because even if fifty CVNs co-signed the proof only **one** signature (64 bytes) needs to be stored and verified in the blockchain.

## Conclusion
This document outlines the concepts and techniques used to implement the proof-of-cooperation blockchain algorithm, and should make it easier to read and understand the source code of Pyloncoin.  With PoC I have tried to create a system which incorporates centrally organised democratic processes, but which is decentralised from a technical point of view.  There is no need for expensive hardware equipment nor to waste a huge amount of energy in order to successfully run a decentralised public blockchain.

Notes
-----
[1] https://pylon-network.org/pyloncoin2.html  
[2] https://github.com/pyloncoin/pyloncoin.git  
[3] https://www.pjrc.com/teensy/  
[4] https://github.com/pyloncoin/Fasito.git  
[5] https://github.com/pyloncoin/secp256k1-mc-arm.git  

