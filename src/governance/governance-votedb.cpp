/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   governance-votedb.cpp
 * Author: ander
 * 
 * Created on 29 de julio de 2018, 14:05
 */

#include "governance-votedb.h"
#include "governance.h"

GovernanceObjectVoteFile::GovernanceObjectVoteFile() : nMemoryVotes(0), listVotes(), mapVoteIndex() {
}

GovernanceObjectVoteFile::GovernanceObjectVoteFile(const GovernanceObjectVoteFile& other) 
    : nMemoryVotes(other.nMemoryVotes), listVotes(other.listVotes), mapVoteIndex()  {
    RebuildIndex();
}

void GovernanceObjectVoteFile::AddVote(const GovernanceObject& vote) {
    uint256 nHash = vote.GetHash();
    
    if (HasVote(vote)) {
        return;
    }
    
    listVotes.push_front(vote);
    mapVoteIndex.emplace(nHash, listVotes.begin());
    ++nMemoryVotes;
}


bool GovernanceObjectVoteFile::HasVote(const GovernanceObject& vote) {
    return mapVoteIndex.find(vote.GetHash()) != mapVoteIndex.end();
}

bool GovernanceObjectVoteFile::SerializeVoteToStream(const uint256& nHash, CDataStream& ss) const
{
    vote_m_cit it = mapVoteIndex.find(nHash);
    if(it == mapVoteIndex.end()) {
        return false;
    }
    ss << *(it->second);
    return true;
}

void GovernanceObjectVoteFile::RemoveVotesFromId(const string candidateId) {
    vote_l_it it = listVotes.begin();
    while (it != listVotes.end()) {
        if (it->candidateId == candidateId) {
            --nMemoryVotes;
            mapVoteIndex.erase(it->GetHash());
            listVotes.erase(it++);
        } else {
            ++it;
        }
    }
}

void GovernanceObjectVoteFile::RebuildIndex() {
    mapVoteIndex.clear();
    nMemoryVotes = 0;
    vote_l_it it = listVotes.begin();
    
    while (it != listVotes.end()) {
        GovernanceObject& vote = *it;
        uint256 nHash = vote.GetHash();
        if (mapVoteIndex.find(nHash) == mapVoteIndex.end()) {
            mapVoteIndex[nHash] = it;
            ++nMemoryVotes;
            ++it;
        } else {
            listVotes.erase(it++);
        }
    }
}