/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   governance.cpp
 * Author: ander
 * 
 * Created on 29 de julio de 2018, 12:21
 */

#include "governance/governance.h"
#include "main.h"
#include "primitives/transaction.h"

GovernanceObject::GovernanceObject(int32_t version, uint256 txhash, int32_t vout, CSchnorrSig sig, int32_t type, int64_t time, string id, bool vote) : nVersion(version), txhash(txhash), txvout(vout), creatorSignature(sig), govType(type), timestamp(time), candidateId(id), vote(vote) {}

uint256 GovernanceObject::GetHash() {
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

bool GovernanceObject::HasMinimumAmount() {
    
    CAmount amount = GovernanceObject::MIN_VOTE_AMOUNT_PROSUMER;
    
    if (this->govType == CVN_VOTE) {
        amount = GovernanceObject::MIN_VOTE_AMOUNT_CVN;
    }
    
    CTransactionRef tx;
    uint256 hashBlock;
    
    if (GetTransaction(txhash, tx, Params().GetConsensus(), hashBlock, true)) {
        return tx->vout[txvout].nValue >= amount;
    }
    
    return false;
    
}
