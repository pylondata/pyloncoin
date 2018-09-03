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
#include "base58.h"

using namespace std;

static const int32_t CVN_VOTE = 0;
static const int32_t PROSUMER_VOTE = 1;

class GovernanceObject {
public:
    
    static const int32_t GOVERNANCE_DEFAULT_VERSION = 1;
    static const int32_t GOVERNANCE_CURRENT_VERSION = GOVERNANCE_DEFAULT_VERSION;
    
    static const uint64_t MAX_VOTING_TIME = 15 * 60 * 60 * 24; //15 days
    static const int32_t MIN_VOTE_THRESHOLD = 10;
    static const int32_t MIN_AMOUNT_CONFIRMATIONS = 1;
    static const CAmount MIN_VOTE_AMOUNT_PROSUMER = 1000 * COIN;
    static const CAmount MIN_VOTE_AMOUNT_CVN = 2000 * COIN;
    
    int32_t nVersion;
    uint256 txhash;
    int32_t txvout;
    std::vector<unsigned char> voterSignature;
    int32_t voterId;
    int32_t govType;
    string candidateId;
    bool vote;
    
    GovernanceObject();
   
    GovernanceObject(int32_t version, uint256 txhash, int32_t txvout, std::vector<unsigned char> voterSignature, int32_t voterId, int32_t govType, string candidateId, bool vote);
    
    GovernanceObject(const GovernanceObject& gobj);
    
    uint256 GetHash();
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        READWRITE(txhash);
        READWRITE(txvout);
        READWRITE(voterSignature);
        READWRITE(voterId);
        READWRITE(govType);
        READWRITE(candidateId);
        READWRITE(vote);
    }
        
    bool operator == (GovernanceObject& gobj) {
        return gobj.GetHash() == this->GetHash();
    }
    
    bool HasMinimumAmount();
    
    bool GetOutputAddress(CBitcoinAddress& address);
    
};
#endif /* GOVERNANCE_H */
