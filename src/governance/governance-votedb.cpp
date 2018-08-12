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

GovernanceObjectVoteDB::GovernanceObjectVoteDB() {
    boost::filesystem::path path = GetDefaultDataDir();
    boost::filesystem::path governancePath = path / "governance";
    db = new CDBWrapper(governancePath, DEFAULT_CACHE_SIZE, false, false, false);
}

void GovernanceObjectVoteDB::AddVote(GovernanceObject& vote) {
    uint256 nHash = vote.GetHash();

    if (HasVote(vote)) {
        return;
    }

    db->Write(nHash, vote, true);

    vector<uint256> votes;
    votes.reserve(1);

    votes.push_back(nHash);
    db->Write(vote.candidateId, votes);
}

bool GovernanceObjectVoteDB::HasVote(GovernanceObject& vote) {
    return db->Exists(vote.GetHash());
}

bool GovernanceObjectVoteDB::SerializeVoteToStream(uint256& nHash, CDataStream& ss) const {
    GovernanceObject gObj;

    if (db->Read(nHash, gObj)) {
        ss << gObj;
        return true;
    }

    return false;
}

void GovernanceObjectVoteDB::RemoveVotesFromId(string candidateId) {
    vector<uint256> votes;
    db->Read(candidateId, votes);

    for (vector<uint256>::iterator it = votes.begin(); it != votes.end(); ++it) {
        uint256 nHash = *it;
        db->Erase(nHash, true);
    }

    db->Erase(candidateId, true);
}

int GovernanceObjectVoteDB::GetVotesCountFromId(string candidateId) {
    vector<uint256> votes;
    db->Read(candidateId, votes);

    return votes.size();
}