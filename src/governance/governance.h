/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   governance.h
 * Author: ander
 *
 * Created on 29 de julio de 2018, 12:21
 */

#ifndef GOVERNANCE_H
#define GOVERNANCE_H

#include <string>
#include "primitives/cvn.h"
#include "hash.h"
#include "serialize.h"
#include "uint256.h"
#include "amount.h"

using namespace std;

static const uint32_t CVN_VOTE = 1;
static const uint32_t PROSUMER_VOTE = 2;

class GovernanceObject {
public:
    
    static const uint64_t MAX_VOTING_TIME = 15 * 60 * 60 * 24; //15 days
    static const uint32_t MIN_VOTE_THRESHOLD = 10;
    static const uint32_t MIN_AMOUNT_CONFIRMATIONS = 1;
    static const CAmount MIN_VOTE_AMOUNT_PROSUMER = 1000 * COIN;
    static const CAmount MIN_VOTE_AMOUNT_CVN = 2000 * COIN;
    
    uint32_t nVersion;
    uint256 txhash;
    uint32_t txvout;
    CSchnorrSig creatorSignature;
    uint32_t govType;
    string candidateId;
    bool vote;
    
    GovernanceObject();
   
    GovernanceObject(uint32_t version, uint256 txhash, uint32_t txvout, CSchnorrSig creatorSignature, uint32_t govType, string candidateId, bool vote);
    
    GovernanceObject(const GovernanceObject& gobj);
    
    uint256 GetHash();
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(txhash);
        READWRITE(txvout);
        READWRITE(creatorSignature);
        READWRITE(govType);
        READWRITE(candidateId);
        READWRITE(vote);
    }
        
    bool operator == (GovernanceObject& gobj) {
        return gobj.GetHash() == this->GetHash();
    }
    
    bool HasMinimumAmount();
    
};
#endif /* GOVERNANCE_H */
