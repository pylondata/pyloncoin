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

static const int32_t CVN_VOTE = 1;
static const int32_t PROSUMER_VOTE = 2;

class GovernanceObject {
public:
    
    static const int64_t MAX_VOTING_TIME = 15 * 60 * 60 * 24; //15 days
    static const int32_t MIN_VOTE_THRESHOLD = 10;
    static const int32_t MIN_AMOUNT_CONFIRMATIONS = 1;
    static const CAmount MIN_VOTE_AMOUNT_PROSUMER = 1000 * COIN;
    static const CAmount MIN_VOTE_AMOUNT_CVN = 2000 * COIN;
    
    int32_t nVersion;
    uint256 txhash;
    int32_t txvout;
    CSchnorrSig creatorSignature;
    int32_t govType;
    int64_t timestamp;
    string candidateId;
    bool vote;
    
    GovernanceObject(int32_t version, uint256 txhash, int32_t txvout, CSchnorrSig creatorSignature, int32_t govType, int64_t timestamp, string candidateId, bool vote);
    
    uint256 GetHash();
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(txhash);
        READWRITE(txvout);
        READWRITE(creatorSignature);
        READWRITE(govType);
        READWRITE(timestamp);
        READWRITE(candidateId);
        READWRITE(vote);
    }
        
    bool operator == (const GovernanceObject& gobj) {
        return this->creatorSignature == gobj.creatorSignature &&
                this->govType == gobj.govType &&
                this->candidateId == gobj.candidateId;
    }
    
    bool HasMinimumAmount();
    
};
#endif /* GOVERNANCE_H */
