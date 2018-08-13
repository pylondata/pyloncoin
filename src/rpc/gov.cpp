/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   gov.cpp
 * Author: ander
 * 
 * Created on 13 de agosto de 2018, 12:17
 */

#include "server.h"
#include "governance/governance.h"
#include "governance/governance-votedb.h"
#include "fasito/fasito.h"
#include "fasito/cert.h"
#include "net.h"
#include "init.h"
#include "main.h"
#include "poc.h"
#include "base58.h"

#include <univalue.h>

void GovernanceObjectToJSON(const GovernanceObject& gobj, UniValue& entry) {
    entry.push_back(Pair("version", gobj.nVersion));
    entry.push_back(Pair("txhash", gobj.txhash.GetHex()));
    entry.push_back(Pair("txvout", gobj.txvout));
    entry.push_back(Pair("votetype", gobj.govType ? "CVN_VOTE" : "PROSUMER_VOTE"));
    entry.push_back(Pair("candidateid", gobj.candidateId));
    entry.push_back(Pair("voterid", gobj.voterId));
    entry.push_back(Pair("signature", EncodeBase64(&gobj.voterSignature[0], gobj.voterSignature.size())));
}

UniValue getvotescountfromid(const JSONRPCRequest& request)
{
    const UniValue params = request.params;
    if (request.fHelp || params.size() < 1){
        throw runtime_error(
            "getvotescountfromid \"candidateid\"\n"
            "Return the number of success votes of the candidate\n"
                
            "\nArguments:\n"
            "1. \"candidateid\"      (string, required) The candidate id\n"
                
            "\nResult:\n"
            "\"number\"      Number of success votes."
        );
    }
    
    string candidateId;
    UniValue v = params[0];
    
    if (v.isStr()) {
        candidateId = v.get_str();
        
        int votes = voteDb->GetVotesCountFromId(candidateId);
        
        LOCK(cs_main);
        return votes;
    }
    
    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid candidate Id");
        
}

UniValue makevote(const JSONRPCRequest& request)
{
    const UniValue params = request.params;
    if (request.fHelp || params.size() < 5){
        throw runtime_error(
            "makevote \"candidateid\" \"votetype\" \"txhash\" \"vout\" \"vote\"\n"
            "Votes the candidate\n"
                
            "\nArguments:\n"
            "1. \"candidateid\"      (string, required) The candidate id.\n"
            "2. \"votetype\"         (integer, required) The type of vote (0 => CVN, 1 => PROSUMER).\n"             
            "3. \"txhash\"           (hex, required) The tx hash to check amount to vote.\n"
            "4. \"vout\"             (integer, required) The index of txout to check amount to vote.\n"
            "5. \"vote\"             (integer, required) The vote (0 => Disagree, 1 => Agree).\n"
                
            "\nResult:\n"
            "\"votedata\"            Data of vote."
        );
    }
    
    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();
    
    GovernanceObject* gobj = new GovernanceObject();
    
    UniValue candidateVal = params[0];
    UniValue voteTypeVal = params[1];
    UniValue txhashVal = params[2];
    UniValue voutVal = params[3];
    UniValue voteVal = params[4];
    
    if (candidateVal.isStr()) {
        gobj->candidateId = candidateVal.get_str();
    } else {
        throw JSONRPCError(RPC_PARSE_ERROR, "The param \"candidate\" must be a string");
    }
    
    if (voteTypeVal.isNum()) {
        gobj->govType = voteTypeVal.get_int();
        if (gobj->govType != CVN_VOTE && gobj->govType != PROSUMER_VOTE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "The param \"votetype\" must be 0 or 1");
        }
    } else {
        throw JSONRPCError(RPC_PARSE_ERROR, "The param \"votetype\" must be a number");
    }
    
    uint256 txhash = ParseHashV(txhashVal, "");
    gobj->txhash = txhash;
    
    if (voutVal.isNum()) {
        gobj->txvout = voutVal.get_int();
    } else {
        throw JSONRPCError(RPC_PARSE_ERROR, "The param \"vout\" must be a number.");
    }
    
    if (voteVal.isNum()) {
        gobj->vote = voteVal.get_int() > 0;
    } else {
        throw JSONRPCError(RPC_PARSE_ERROR, "The param \"vote\" must be a number.");
    }
    
    if (gobj->HasMinimumAmount()) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "The transaction output does not reach the minimum required.");
    }
    
    CBitcoinAddress address;

    if (gobj->GetOutputAddress(address)) {

        CKeyID keyID;
        if (!address.GetKeyID(keyID)) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
        }

        CKey key;
        if (!pwalletMain->GetKey(keyID, key)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
        }
        
        CHashWriter ss(SER_GETHASH, 0);
        ss << strMessageMagic;
        ss << nCvnNodeId;
        
        vector<unsigned char> vchSig;
        if (!key.SignCompact(ss.GetHash(), vchSig)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
        }
        
        gobj->voterSignature = vchSig;
        
        //Share vote
        if (!voteDb->HasVote(*gobj)) {
            voteDb->AddVote(*gobj);
            RelayGovernanceObject(*gobj);
        }
        
        UniValue result(UniValue::VOBJ);
        GovernanceObjectToJSON(*gobj, result);
        
        return result;
        
    }
    
    throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    
}