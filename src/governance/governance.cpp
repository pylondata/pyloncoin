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
#include "script/script.h"
#include "script/standard.h"
#include "net.h"
#include "main.h"
#include "poc.h"


#include <boost/thread.hpp>

GovernanceObject::GovernanceObject() : nVersion(GOVERNANCE_CURRENT_VERSION), txhash(), txvout(0), voterSignature(), voterId(0), govType(0), candidateId(""), vote(false) {}


GovernanceObject::GovernanceObject(int32_t version, uint256 txhash, int32_t vout, std::vector<unsigned char> sig, uint32_t voterId, int32_t type, string id, bool vote) : nVersion(version), txhash(txhash), txvout(vout), voterSignature(sig), voterId(voterId), govType(type), candidateId(id), vote(vote) {}

GovernanceObject::GovernanceObject(const GovernanceObject& gobj) : nVersion(gobj.nVersion), txhash(gobj.txhash), txvout(gobj.txvout), voterSignature(gobj.voterSignature), voterId(gobj.voterId), govType(gobj.govType), candidateId(gobj.candidateId), vote(gobj.vote) {}


uint256 GovernanceObject::GetHash() const {
    return SerializeHash(*this, SER_GETHASH, GOVERNANCE_CURRENT_VERSION);
}

bool GovernanceObject::HasMinimumAmount() const {
    
    CAmount amount = GovernanceObject::MIN_VOTE_AMOUNT_PROSUMER;
    
    if (this->govType == CVN_VOTE) {
        amount = GovernanceObject::MIN_VOTE_AMOUNT_CVN;
    }
    
    CTransaction tx;
    uint256 hashBlock;
    
    if (GetTransaction(txhash, tx, Params().GetConsensus(), hashBlock, true)) {
        return tx.vout[this->txvout].nValue >= amount;
    }
    
    return false;
    
}

bool GovernanceObject::GetOutputAddress(CBitcoinAddress& address) const {
    CTransaction tx;
    uint256 hashBlock;
    
    if (GetTransaction(txhash, tx, Params().GetConsensus(), hashBlock, true)) {
        CTxOut txout = tx.vout[this->txvout];
        
        CTxDestination dest;
        if (ExtractDestination(txout.scriptPubKey, dest)) {
            address = *(new CBitcoinAddress(dest));
            return true;
        }
        
        return false;
    }
    
    return false;
}

bool GovernanceObject::CheckSignature() const {
    CBitcoinAddress address;
    if (!GetOutputAddress(address)) {
        return false;
    }
    
    CKeyID keyID;
    if (!address.GetKeyID(keyID)) {
        return false;
    }
    
    bool fInvalid = false;
    std::string str(voterSignature.begin(), voterSignature.end());
    vector<unsigned char> vchSig = DecodeBase64(str.c_str(), &fInvalid);
    
    if (fInvalid) {
        return false;
    }
    
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << voterId;
    
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
        return false;
    }
    
    return (pubkey.GetID() == keyID);
}

void RelayGovernanceObject(const GovernanceObject& gobj) {
    CInv inv(MSG_GOV, gobj.GetHash());
    
    {
        LOCK(cs_mapRelayVotes);
        mapRelayVotes.insert(std::make_pair(inv.hash, gobj));
    }
    
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        pnode->PushInventory(inv);
    }
}
