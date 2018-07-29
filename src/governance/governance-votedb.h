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
#include <governance/governance.h>
#include "serialize.h"
#include "streams.h"
#include "uint256.h"


using namespace std;

class GovernanceObjectVoteFile {
public:
    typedef std::list<GovernanceObject> vote_l_t;

    typedef vote_l_t::iterator vote_l_it;

    typedef vote_l_t::const_iterator vote_l_cit;

    typedef std::map<uint256,vote_l_it> vote_m_t;

    typedef vote_m_t::iterator vote_m_it;

    typedef vote_m_t::const_iterator vote_m_cit;
    
    GovernanceObjectVoteFile();
    
    GovernanceObjectVoteFile(const GovernanceObjectVoteFile& other);
    
    void AddVote(const GovernanceObject& vote);
    
    bool HasVote(const GovernanceObject& vote);
    
    void RemoveVotesFromId(const string candidateId);
    
    int GetVotesCountFromId(const string candidateId);
    
    bool SerializeVoteToStream(const uint256& nHash, CDataStream& ss) const;
    
    int GetVoteCount() {
        return nMemoryVotes;
    }
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nMemoryVotes);
        READWRITE(listVotes);
        if(ser_action.ForRead()) {
            RebuildIndex();
        }
    }
    
private:
    int nMemoryVotes;
    vote_l_t listVotes;
    map<uint256, vote_l_t> mapVoteIndex;
    
    void RebuildIndex();
};
#endif /* GOVERNANCE_VOTEDB_H */
