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

GovernanceObject::GovernanceObject() : nVersion(0), txhash(), txvout(0), creatorSignature(), govType(0), candidateId(""), vote(false) {}


GovernanceObject::GovernanceObject(uint32_t version, uint256 txhash, uint32_t vout, CSchnorrSig sig, uint32_t type, string id, bool vote) : nVersion(version), txhash(txhash), txvout(vout), creatorSignature(sig), govType(type), candidateId(id), vote(vote) {}

GovernanceObject::GovernanceObject(const GovernanceObject& gobj) : nVersion(gobj.nVersion), txhash(gobj.txhash), txvout(gobj.txvout), creatorSignature(gobj.creatorSignature), govType(gobj.govType), candidateId(gobj.candidateId), vote(gobj.vote) {}


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
