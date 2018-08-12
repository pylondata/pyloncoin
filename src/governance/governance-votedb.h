/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   governance-votedb.h
 * Author: ander
 *
 * Created on 29 de julio de 2018, 14:05
 */

#ifndef GOVERNANCE_VOTEDB_H
#define GOVERNANCE_VOTEDB_H

#include <list>
#include <map>
#include <string>
#include "dbwrapper.h"
#include "governance/governance.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"


using namespace std;

static const size_t DEFAULT_CACHE_SIZE = 80 * 1024 * 1024 * 1024; //80 MB

class GovernanceObjectVoteDB {
public:
    GovernanceObjectVoteDB();
    
    void AddVote(GovernanceObject& vote);
    
    bool HasVote(GovernanceObject& vote);
    
    void RemoveVotesFromId(string candidateId);
    
    int GetVotesCountFromId(string candidateId);
    
    bool SerializeVoteToStream(uint256& nHash, CDataStream& ss) const;
    
    int GetVoteCount() {
        return db->NewIterator()->GetKeySize();
    }
    
private:
    CDBWrapper* db;
};
#endif /* GOVERNANCE_VOTEDB_H */
