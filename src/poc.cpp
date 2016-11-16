// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"
#include "util.h"
#include "poc.h"
#include "main.h"
#include "timedata.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "net.h"
#include "miner.h"
#include "init.h"
#include "cvn.h"

#ifdef USE_OPENSC
#include "smartcard.h"
#endif

#include <secp256k1.h>
#include <secp256k1_schnorr.h>
#include <boost/thread.hpp>
#include <stdio.h>
#include <set>

// changing this is a consensus change
#define POC_BLOCKS_TO_SCAN 200

#define POC_DEBUG 0

CCriticalSection cs_mapChainAdmins;
ChainAdminMapType mapChainAdmins;

CCriticalSection cs_mapCVNs;
CvnMapType mapCVNs;

CCriticalSection cs_mapCvnSigs;
CvnSigMapType mapCvnSigs;

CCriticalSection cs_mapCvnNonces;
CvnNonceMapType mapCvnNonces;

CCriticalSection cs_mapChainData;
ChainDataMapType mapChainData;

CCriticalSection cs_mapBlockIndexByPrevHash;
BlockIndexByPrevHashType mapBlockIndexByPrevHash;

CCriticalSection cs_mapBannedCVNs;
BannedCVNMapType mapBannedCVNs;

static CSchnorrPrivNonce cvnNoncePrivate;
static secp256k1_context *secp256k1_context_none = NULL;

#if POC_DEBUG
string bin2hex(const uint8_t *buf, const size_t len)
{
    size_t i;
    char c[3];
    string res;

    for (i = 0; i < len; i++) {
        sprintf(c, "%02x", buf[i]);
        res.append(c);
    }

    return res;
}

void printHex(const uint8_t *buf, const size_t len, const bool addLF = false)
{
    cout << bin2hex(buf, len);

    if (addLF)
        cout << endl;
}
#endif

bool static CreateNonceWithKey(const uint256& hashUnsignedBlock, const CKey cvnPrivKey, CSchnorrPrivNonce& noncePrivate, CCvnPubNonce& noncePublic, const CCvnInfo& cvnInfo)
{
    if (cvnInfo.pubKey != cvnPubKey) {
        LogPrintf("CreateNonceWithKey : key does not match node ID\n"
                "  block chain pubkey: %s\n"
                "  FASITO/FILE pubkey: %s\n", cvnInfo.pubKey.ToString(), cvnPubKey.ToString());
        return false;
    }

    if (!cvnPrivKey.SchnorrCreateNoncePair(hashUnsignedBlock, noncePublic.pubNonce, noncePrivate)) {
        LogPrintf("CreateNonceWithKey : could not create block signature\n");
        return false;
    }

#if POC_DEBUG
    LogPrintf("CreateNonceWithKey : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n  pubn: %s\n privn: %s\n",
            hashUnsignedBlock.ToString(), noncePublic.nSignerId,
            cvnInfo.pubKey.ToString(),
            noncePublic.ToString(),
            noncePrivate.ToString());
#endif
    return true;
}

static bool CreateNoncePairForHash(const uint256& hashToSign, CCvnPubNonce& noncePublic, const uint32_t& nNodeId)
{
    if (!nNodeId) {
        LogPrintf("CreateNoncePairForHash : CVN node not initialized\n");
        return false;
    }

    if (!mapCVNs.count(nNodeId)) {
        LogPrintf("CreateNoncePairForHash : could not find CvnInfo for signer ID 0x%08x\n", nNodeId);
        return false;
    }

    if (!mapArgs.count("-cvn")) {
        LogPrintf("CreateNoncePairForHash : this node was not configured to run as CVN\n", nNodeId);
        return false;
    }

    noncePublic.nSignerId  = nNodeId;
    CCvnInfo cvnInfo = mapCVNs[nNodeId];

    if (GetArg("-cvn", "") == "fasito") {
#ifdef USE_FASITO
        if (!fSmartCardUnlocked) {
            LogPrint("cvn", "CreateNoncePairForHash : ERROR, smart card not unlocked. Make sure that -cvnpin, -cvnslot and -cvnkeyid are set correctly\n");
            return false;
        }
        if (!CvnSignWithFasito(hashToSign, signature, cvnInfo)) {
            noncePublic.SetNull();
            return false;
        }
#else
        LogPrintf("CreateNoncePairForHash : ERROR, this wallet was not compiled with Fasito support\n");
        return false;
#endif
    } else {
        if (!CreateNonceWithKey(hashToSign, cvnPrivKey, cvnNoncePrivate, noncePublic, cvnInfo)) {
            noncePublic.SetNull();
            return false;
        }
    }

    return true;
}

static bool CreateCvnNoncePair(const uint256& hashCurrentTip, CCvnPubNonce& noncePublic, const uint32_t& nNextCreator, const uint32_t& nNodeId)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashCurrentTip << nNextCreator << nNodeId;

    return CreateNoncePairForHash(hasher.GetHash(), noncePublic, nNodeId);
}

bool static CvnSignWithKey(const uint256& hashToSign, const CKey& cvnPrivKey, CSchnorrSig& signature)
{
    if (!cvnPrivKey.SchnorrSign(hashToSign, signature)) {
        LogPrintf("CvnSignWithKey : could not create chain signature\n");
        return false;
    }

    if (!CvnVerifySignature(hashToSign, signature, cvnPubKey)) {
        LogPrintf("CvnSignWithKey : created invalid signature\n");
        return false;
    }

#if POC_DEBUG
    LogPrintf("CvnSignWithKey : OK\n  Hash: %s\n  pubk: %s\n   sig: %s\n",
            hashToSign.ToString(),
            cvnPubKey.ToString(),
            signature.ToString());
#endif
    return true;
}

bool static CvnSignPartialWithKey(const uint256& hashUnsignedBlock, const CKey& cvnPrivKey, const secp256k1_pubkey& sumPublicKeysOthers, CCvnPartialSignature& signature)
{
    if (cvnNoncePrivate.IsNull()) {
        LogPrintf("CvnSignPartialWithKey : could not create chain signature no private nonce available\n");
        return false;
    }

    if (!cvnPrivKey.SchnorrSignParial(hashUnsignedBlock, sumPublicKeysOthers, cvnNoncePrivate, signature.signature)) {
        LogPrintf("CvnSignPartialWithKey : could not create chain signature\n");
        return false;
    }

#if POC_DEBUG
    LogPrintf("CvnSignPartialWithKey : OK\n  Hash: %s\nsigner: 0x%08x\n   sum: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), signature.nSignerId,
            in2hex(sumPublicKeysOthers.data, 64), signature.ToString());
#endif
    return true;
}

bool CvnSignHash(const uint256 &hashToSign, CSchnorrSig& signature)
{
    if (GetArg("-cvn", "") == "fasito") {
#if 0
        if (!fSmartCardUnlocked) {
            LogPrint("cvn", "CvnSignHash : ERROR, smart card not unlocked. Make sure that -cvnpin, -cvnslot and -cvnkeyid are set correctly\n");
            return false;
        }
        return CvnSignWithSmartCard(hashToSign, signature, cvnInfo);
#else
        LogPrintf("CvnSignHash : ERROR, this wallet was not compiled with smart card support\n");
        return false;
#endif
    } else {
        return CvnSignWithKey(hashToSign, cvnPrivKey, signature);
    }

}

bool CvnSignPartial(const uint256& hashPrevBlock, CCvnPartialSignature& signature, const uint32_t& nNextCreator, const uint32_t& nNodeId)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashPrevBlock << nNextCreator; // test if we could include << nNodeId (well, probably not)

    uint256 hashToSign = hasher.GetHash();

    if (!nNodeId) {
        LogPrintf("CvnSignPartial : CVN node not initialised\n");
        return false;
    }

    if (!mapCVNs.count(nNodeId)) {
        LogPrintf("CvnSignPartial : could not find CvnInfo for signer ID 0x%08x\n", nNodeId);
        return false;
    }

    if (!mapArgs.count("-cvn")) {
        LogPrintf("CvnSignPartial : this node was not configured to run as CVN\n");
        return false;
    }

    signature.nSignerId = nNodeId;

    /* create a plain schnorr signature in case only one CVN is available (e.g. during bootstrap) */
    if (mapCVNs.size() == 1)
        return CvnSignHash(hashToSign, signature.signature);

    LOCK(cs_mapCvnNonces);
    CvnNonceCreatorType& mapNoncesByCreators = mapCvnNonces[hashPrevBlock];
    CvnNonceSignerType& mapNoncesBySigner = mapNoncesByCreators[nNextCreator];

    vector<secp256k1_pubkey *> allPubOtherNonces;
    vector<uint32_t> vMissingSignerIds;

    BOOST_FOREACH(const CvnNonceSignerType::value_type& entry, mapNoncesBySigner) {
        const CCvnPubNonceMsg& pubNonce = entry.second;

        /* Skip this nodes entry. We have to crate the sum of all the others */
        if (pubNonce.nSignerId == nNodeId)
            continue;

        allPubOtherNonces.push_back((secp256k1_pubkey *)&entry.second.pubNonce);
    }

    secp256k1_pubkey sumPublicKeysOthers;
    memset(sumPublicKeysOthers.data, 0, 64);
    if (allPubOtherNonces.size() > 1) {
        if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, &sumPublicKeysOthers, &allPubOtherNonces[0], allPubOtherNonces.size())) {
            LogPrintf("CvnSignPartial : could not combine nonces\n");
            return false;
        }
    } else if (allPubOtherNonces.size() == 1) {
        //printHex((uint8_t *)allPubOtherNonces[0], 64, true);
        memcpy(sumPublicKeysOthers.data, allPubOtherNonces[0], 64);
    } else {
        LogPrintf("CvnSignPartial : ERROR: not enough nonces avaialbe\n");
        return false;
    }

    if (GetArg("-cvn", "") == "fasito") {
#ifdef USE_OPENSC
        if (!fSmartCardUnlocked) {
            LogPrint("cvn", "CvnSignPartial : ERROR, smart card not unlocked. Make sure that -cvnpin, -cvnslot and -cvnkeyid are set correctly\n");
            return false;
        }
        CCvnInfo cvnInfo = mapCVNs[nNodeId];

        if (!CvnSignWithSmartCard(hashToSign, signature, cvnInfo))
            return false;
#else
        LogPrintf("CvnSignPartial : ERROR, this wallet was not compiled with smart card support\n");
        return false;
#endif
    } else {
        //LogPrintf(":::TEST: %s / %s\n", bin2hex(sumPublicKeysOthers.data, 64), bin2hex((uint8_t *)allPubOtherNonces[0], 64));
        if (!CvnSignPartialWithKey(hashToSign, cvnPrivKey, sumPublicKeysOthers, signature))
            return false;
    }

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
    {
        if (mapNoncesBySigner.count(cvn.first))
            vMissingSignerIds.push_back(cvn.first);
    }

    signature.vMissingPubNonces = vMissingSignerIds;

    // TODO: validate the partial signature (if even possible)
    return true;
}

int CombinePartialSignatures(CSchnorrSig& allsig, uint8_t *sigs[], int nSignatures)
{
    if (nSignatures < 2)
        return false;

    LogPrint("cvnsig", "CombinePartialSignatures : combining %u signautres\n", nSignatures);
    return secp256k1_schnorr_partial_combine(secp256k1_context_none, allsig.begin(), sigs, nSignatures);
}

bool CvnSignBlock(CBlock& block)
{
    CCvnInfo cvnInfo = mapCVNs[block.nCreatorId];

    if (cvnInfo.pubKey != cvnPubKey) {
        LogPrintf("CvnSignBlock : key does not match node ID\n"
                "  block chain pubkey: %s\n"
                "         FILE pubkey: %s\n", cvnInfo.pubKey.ToString(), cvnPubKey.ToString());
        return false;
    }

    if (!mapCVNs.count(block.nCreatorId)) {
        LogPrintf("CvnSignBlock : could not find CvnInfo for signer ID 0x%08x\n", block.nCreatorId);
        return false;
    }

    if (!mapArgs.count("-cvn")) {
        LogPrintf("CvnSignBlock : this node was not configured to run as CVN\n");
        return false;
    }

    if (!CvnSignHash(block.GetHash(), block.creatorSignature))
        return false;

    return true;
}

bool CvnVerifyChainSignature(const CBlockHeader& block)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << block.hashPrevBlock << block.nCreatorId;

    uint256 hash = hasher.GetHash();

    /* special case when bootstrapping the blockchain we have one CVN ID only */
    if (mapCVNs.size() == 1) {
        if (!mapCVNs.count(block.nCreatorId)) {
            LogPrintf("CvnVerifyChainSignature : could not find CvnInfo for signer ID 0x%08x\n", block.nCreatorId);
            return false;
        }

        if (!CPubKey::VerifySchnorr(hash, block.chainMultiSig, mapCVNs[block.nCreatorId].pubKey)) {
            LogPrintf("CvnVerifyChainSignature : could not verify single sig %s for hash %s for node Id 0x%08x\n", block.chainMultiSig.ToString(), hash.ToString(), block.nCreatorId);
            return false;
        } else {
            return true;
        }
    }

    int count = 0;
    secp256k1_pubkey *allSignersPubkeys[MAX_NUMBER_OF_CVNS];
    vector<uint32_t> vMissingChainIds = block.vMissingCreatorIds;

    // TODO: we should really cache this somehow...
    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
    {
        if (!vMissingChainIds.empty() && find(vMissingChainIds.begin(), vMissingChainIds.end(), cvn.first) != vMissingChainIds.end())
            continue;

        allSignersPubkeys[count++] = (secp256k1_pubkey *)&cvn.second.pubKey.begin()[0];
    }

    secp256k1_pubkey sumOfAllSignersPubkeys;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, &sumOfAllSignersPubkeys, allSignersPubkeys, count))
        return error("could not combine signers public keys");

    CSchnorrPubKey pubK(sumOfAllSignersPubkeys.data);
    if (!CvnVerifySignature(hash, block.chainMultiSig, pubK))
        return error("could not verify chain signature for block %s: %s", hash.ToString(), block.chainMultiSig.ToString());

    return true;
}

bool CvnVerifySignature(const uint256 &hash, const CSchnorrSig &sig, const CSchnorrPubKey &pubKey)
{
    if (!CPubKey::VerifySchnorr(hash, sig, pubKey))
        return false;

    return true;
}

bool CvnVerifySignature(const uint256 &hash, const CSchnorrSig &sig, const uint32_t nCvnId)
{
    if (!mapCVNs.count(nCvnId)) {
        LogPrintf("ERROR: could not find CvnInfo for signer ID 0x%08x\n", nCvnId);
        return false;
    }


    if (!CvnVerifySignature(hash, sig, mapCVNs[nCvnId].pubKey)) {
        LogPrintf("could not verify sig %s for hash %s for node Id 0x%08x\n", sig.ToString(), hash.ToString(), nCvnId);
        return false;
    }

    return true;
}

bool CvnVerifyAdminSignature(const vector<uint32_t> &vAdminIds, const uint256& hashAdmin, const CSchnorrSig& sig)
{
    if (vAdminIds.empty()) {
        LogPrintf("CvnVerifyAdminSignature : no admin IDs avaialbe for hash: %s\n", hashAdmin.ToString());
        return false;
    }

    /* special case when bootstrapping the blockchain we have one chain admin ID only */
    if (mapChainAdmins.size() == 1) {
        uint32_t nAdminId = mapChainAdmins.begin()->first;
        if (!mapChainAdmins.count(nAdminId)) {
            LogPrintf("CvnVerifyAdminSignature : could not find CChainAdmin for admin ID 0x%08x\n", nAdminId);
            return false;
        }

        if (!CPubKey::VerifySchnorr(hashAdmin, sig, mapChainAdmins[nAdminId].pubKey)) {
            LogPrintf("CvnVerifyAdminSignature : could not verify single sig %s for hash %s for admin Id 0x%08x (%s)\n", sig.ToString(), hashAdmin.ToString(), nAdminId, mapChainAdmins[nAdminId].pubKey.ToString());
            return false;
        } else {
            return true;
        }
    }

    if (mapChainAdmins.size() > 1) {
        LogPrintf("CvnVerifyAdminSignature : multiple admin sigs not yet supported\n");
        return false;
    }

    int count = 0;
    secp256k1_pubkey *allSignersPubkeys[MAX_NUMBER_OF_CHAIN_ADMINS];

    // TODO: we should really cache this somehow...
    BOOST_FOREACH(const ChainAdminMapType::value_type& entry, mapChainAdmins)
    {
        if (find(vAdminIds.begin(), vAdminIds.end(), entry.first) == vAdminIds.end())
            continue;

        allSignersPubkeys[count++] = (secp256k1_pubkey *)entry.second.pubKey.begin();
    }

    secp256k1_pubkey sumOfAllSignersPubkeys;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, &sumOfAllSignersPubkeys, allSignersPubkeys, count))
        return error("could not combine admin signers public keys");

    CSchnorrPubKey pubK(sumOfAllSignersPubkeys.data);
    if (!CvnVerifySignature(hashAdmin, sig, pubK))
        return error("could not verify admin signature: %s", hashAdmin.ToString());

    return true;
}

void RelayChainData(const CChainDataMsg& msg)
{
    CInv inv(MSG_POC_CHAIN_DATA, msg.GetHash());
    {
        LOCK(cs_mapRelayChainData);
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelayChainData.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        mapRelayChainData.insert(std::make_pair(inv.hash, msg));
        vRelayExpiration.push_back(std::make_pair(GetTime() + dynParams.nBlockSpacing, inv.hash));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayTxes) // same TX rules apply to chain data messages
            continue;
        pnode->PushInventory(inv);
    }
}

bool CheckAdminSignature(const vector<uint32_t> &vAdminIds, const uint256 &hashAdmin, const CSchnorrSig &sig, const bool fCoinSupply)
{
    const uint32_t nSigs = vAdminIds.size();

    if (nSigs < dynParams.nMinAdminSigs) {
        LogPrintf("not enough admin signatures supplied (got %u signatures, but need at least %u to sign)\n", nSigs, dynParams.nMinAdminSigs);
        return false;
    }

    if (nSigs > dynParams.nMaxAdminSigs) {
        LogPrintf("too many admin signatures supplied %u (%u max)\n", nSigs, dynParams.nMaxAdminSigs);
        return false;
    }

    if (fCoinSupply && nSigs < dynParams.nMaxAdminSigs) {
        LogPrintf("not enough admin signatures supplied (got %u signatures, but need at least %u to sign for coin supply)\n",
            nSigs, dynParams.nMaxAdminSigs);
        return false;
    }

    return CvnVerifyAdminSignature(vAdminIds, hashAdmin, sig);
}

bool AddChainData(const CChainDataMsg& msg)
{
    if (!CheckAdminSignature(msg.vAdminIds, msg.GetHash(), msg.adminMultiSig, msg.HasCoinSupplyPayload()))
        return false;

    uint256 hashBlock = msg.hashPrevBlock;

    LOCK(cs_mapChainData);
    if (mapChainData.count(hashBlock)) {
        LogPrintf("received duplicate chain data for block %s: %s\n", hashBlock.ToString(), msg.ToString());
        return false;
    }

    mapChainData.insert(std::make_pair(hashBlock, msg));

    LogPrintf("AddChainData : signed by %u (minimum %u) admins of %u to be added after blockHash %s\n",
            msg.vAdminIds.size(), dynParams.nMinAdminSigs, dynParams.nMaxAdminSigs, hashBlock.ToString());

    return true;
}

#if 0
static void printNoncesTree()
{
    BOOST_FOREACH(const CvnNonceMapType::value_type tip, mapCvnNonces) {
        LogPrintf("tip           (%02d): %s\n", mapCvnNonces.size(), tip.first.ToString());
        BOOST_FOREACH(const CvnNonceCreatorType::value_type creator, tip.second) {
            LogPrintf(" next creator (%02d): 0x%08x\n", tip.second.size(), creator.first);
            BOOST_FOREACH(const CvnNonceSignerType::value_type signer, creator.second) {
                LogPrintf("  signer      (%02d): 0x%08x (%s)\n", creator.second.size(), signer.first, signer.second.ToString());
            }
        }
    }
}
#endif

bool AddCvnPubNonce(const CCvnPubNonceMsg& msg)
{
    if (!CvnVerifySignature(msg.GetHash(), msg.msgSig, msg.nSignerId))
        return false;

    LOCK(cs_mapCvnNonces);
    CvnNonceCreatorType& mapNoncesByCreators = mapCvnNonces[msg.hashPrevBlock];
    CvnNonceSignerType& mapNoncesBySigner = mapNoncesByCreators[msg.nCreatorId]; // this adds an element if not already there, that's OK

    if (mapNoncesBySigner.count(msg.nSignerId)) { // already have this, no error
        LogPrintf("AddCvnNoncePair : already have -> %s\n", msg.ToString());
        return true;
    }
    LogPrint("cvnsig", "AddCvnNoncePair : add nonce for 0x%08x by 0x%08x, hash %s\n", msg.nCreatorId, msg.nSignerId, msg.hashPrevBlock.ToString());
    mapNoncesBySigner[msg.nSignerId] = msg;

    //printNoncesTree();
    return true;
}

void SendCVNNonce(const CBlockIndex *pindexNew)
{
    if (IsInitialBlockDownload())
        return;

    uint32_t nNextCreator = CheckNextBlockCreator(pindexNew, GetAdjustedTime());

    if (!nNextCreator) {
        LogPrintf("SendCVNNonce : could not find next block creator\n");
        return;
    }

    uint256 hashPrevBlock = pindexNew->GetBlockHash();

    CCvnPubNonce noncePublic;
    if (!CreateCvnNoncePair(pindexNew->GetBlockHash(), noncePublic, nNextCreator, nCvnNodeId)) {
        LogPrintf("SendCVNNonce : could not create nonce pair for 0x%08x by 0x%08x, hash %s\n",
                nNextCreator, nCvnNodeId, hashPrevBlock.ToString());
        return;
    }

    LogPrintf("SendCVNNonce : created CVN nonce pair for block hash %s, nNextCreator: 0x%08x\n",
            hashPrevBlock.ToString(), nNextCreator);

    CCvnPubNonceMsg msg(noncePublic, hashPrevBlock, nNextCreator);

    CSchnorrSig msgSig;
    if (!CvnSignHash(msg.GetHash(), msgSig)) {
        LogPrintf("SendCVNNonce : could not sign pubNonce message\n");
        return;
    }

    msg.msgSig = msgSig;

    if (AddCvnPubNonce(msg))
        RelayCvnPubNonce(msg);
}

void RelayCvnPubNonce(const CCvnPubNonceMsg& msg)
{
    CInv inv(MSG_CVN_PUB_NONCE, msg.GetHash());
    {
        LOCK(cs_mapRelayNonces);
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelayNonces.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        mapRelayNonces.insert(std::make_pair(inv.hash, msg));
        // we keep them around for 30min. so AlreadyHave() works properly
        vRelayExpiration.push_back(std::make_pair(GetTime() + 1800, inv.hash));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayTxes) // same TX rules apply to pub nonce messages
            continue;

        pnode->PushInventory(inv);
    }
}

void RelayCvnSignature(const CCvnPartialSignatureMsg& msg)
{
    CInv inv(MSG_CVN_SIGNATURE, msg.GetHash());
    {
        LOCK(cs_mapRelaySigs);
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelaySigs.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        mapRelaySigs.insert(std::make_pair(inv.hash, msg));
        // we keep them around for 30min. so AlreadyHave() works properly
        vRelayExpiration.push_back(std::make_pair(GetTime() + 1800, inv.hash));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayTxes) // same TX rules apply to block sig messages
            continue;
        pnode->PushInventory(inv);
    }
}

bool CvnVerifyPartialSignature(const CCvnPartialSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashPrevBlock << nCreatorId;

    if (!mapCVNs.count(nCreatorId)) {
        LogPrintf("CvnVerifyPartialSignature : CVN not found 0x%08x\n", nCreatorId);
        return false;
    }

    // TODO: implement
    //return CvnVerifyChainSignature(hashPrevBlock, signature, mapCVNs[nCreatorId].pubKey);
    return true;
}

bool AddCvnSignature(const CCvnPartialSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId)
{
    if (!CvnVerifyPartialSignature(signature, hashPrevBlock, nCreatorId)) {
        LogPrintf("AddCvnSignature : invalid signature received for 0x%08x by 0x%08x, hash %s\n", nCreatorId, signature.nSignerId, hashPrevBlock.ToString());
        return false;
    }

    LOCK(cs_mapCvnSigs);
    CvnSigCreatorType& mapSigsByCreators = mapCvnSigs[hashPrevBlock];

    CvnSigSignerType& mapSigsBySigner = mapSigsByCreators[nCreatorId]; // this adds an element if not already there, that's OK

    if (mapSigsBySigner.count(signature.nSignerId)) // already have this, no error
        return true;

    LogPrint("cvnsig", "AddCvnSignature : add sig for 0x%08x by 0x%08x, hash %s\n", nCreatorId, signature.nSignerId, hashPrevBlock.ToString());
    mapSigsBySigner[signature.nSignerId] = signature;

    return true;
}

void RemoveCvnSigsAndNonces(const uint256& hashPrevBlock)
{
    {
        LOCK(cs_mapCvnSigs);
        if (mapCvnSigs.count(hashPrevBlock))
            mapCvnSigs.erase(hashPrevBlock);
    }

    {
        LOCK(cs_mapCvnNonces);
        if (mapCvnNonces.count(hashPrevBlock))
            mapCvnNonces.erase(hashPrevBlock);
    }
}

void SendCVNSignature(const CBlockIndex *pTip)
{
    if (IsInitialBlockDownload())
        return;

    uint32_t nNextCreator = CheckNextBlockCreator(pTip, GetAdjustedTime());

    if (!nNextCreator) {
        LogPrintf("SendCVNSignature : could not find next block creator\n");
        return;
    }

    uint256 hashPrevBlock = pTip->GetBlockHash();
    CCvnPartialSignature signature;

    if (!CvnSignPartial(hashPrevBlock, signature, nNextCreator, nCvnNodeId)) {
        LogPrintf("SendCVNSignature : could not create sig for 0x%08x by 0x%08x, hash %s\n",
                nNextCreator, nCvnNodeId, hashPrevBlock.ToString());
        return;
    }

    LogPrintf("SendCVNSignature : created CVN signature for block hash %s, nNextCreator: 0x%08x\n",
            hashPrevBlock.ToString(), nNextCreator);

    CCvnPartialSignatureMsg msg(signature, hashPrevBlock, nNextCreator);

    if (AddCvnSignature(signature, msg.hashPrevBlock, nNextCreator))
        RelayCvnSignature(msg);
}

void PrintAllCVNs()
{
    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs) {
        LogPrint("cvndata", "%s\n", cvn.second.ToString());
    }
}

void PrintAllChainAdmins()
{
    BOOST_FOREACH(const ChainAdminMapType::value_type& adm, mapChainAdmins) {
        LogPrint("cvndata", "%s\n", adm.second.ToString());
    }
}

void UpdateCvnInfo(const CBlock* pblock)
{
    LogPrint("cvn", "UpdateCvnInfo : updating CVN data\n");

    if (!pblock->HasCvnInfo()) {
        LogPrint("cvn", "UpdateCvnInfo : ERROR, block is not of type CVN\n");
        return;
    }

    LOCK(cs_mapCVNs);

    mapCVNs.clear();

    BOOST_FOREACH(CCvnInfo cvnInfo, pblock->vCvns) {
        mapCVNs.insert(std::make_pair(cvnInfo.nNodeId, cvnInfo));
    }

    PrintAllCVNs();
}

void UpdateChainAdmins(const CBlock* pblock)
{
    LogPrint("cvn", "UpdateChainAdmins : updating chain admins\n");

    if (!pblock->HasChainAdmins()) {
        LogPrintf("UpdateChainAdmins : ERROR, block has no CHAIN_ADMINS_PAYLOAD\n");
        return;
    }

    LOCK(cs_mapChainAdmins);

    mapChainAdmins.clear();

    BOOST_FOREACH(CChainAdmin admin, pblock->vChainAdmins) {
        mapChainAdmins.insert(std::make_pair(admin.nAdminId, admin));
    }

    PrintAllChainAdmins();
}

bool CheckDynamicChainParameters(const CDynamicChainParams& params)
{
    if (params.nBlockSpacing > MAX_BLOCK_SPACING || params.nBlockSpacing < MIN_BLOCK_SPACING) {
        LogPrintf("CheckDynamicChainParameters : ERROR, block spacing %u exceeds limit\n", params.nBlockSpacing);
        return false;
    }

    if (params.nTransactionFee > MAX_TX_FEE_THRESHOLD || params.nTransactionFee < MIN_TX_FEE_THRESHOLD) {
        LogPrintf("CheckDynamicChainParameters : ERROR, tx fee threshold %u exceeds limit\n", params.nTransactionFee);
        return false;
    }

    if (params.nDustThreshold > MAX_DUST_THRESHOLD || params.nDustThreshold < MIN_DUST_THRESHOLD) {
        LogPrintf("CheckDynamicChainParameters : ERROR, dust threshold %u exceeds limit\n", params.nDustThreshold);
        return false;
    }

    if (!params.nMinAdminSigs || params.nMinAdminSigs > params.nMaxAdminSigs) {
        LogPrintf("CheckDynamicChainParameters : ERROR, number of CVN signers %u/%u exceeds limit\n", params.nMinAdminSigs, params.nMaxAdminSigs);
        return false;
    }

    if (params.nBlocksToConsiderForSigCheck < MIN_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK || params.nBlocksToConsiderForSigCheck > MAX_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK) {
        LogPrintf("CheckDynamicChainParameters : ERROR, %u blocksToConsiderForSigCheck is out of bounds\n", params.nBlocksToConsiderForSigCheck);
        return false;
    }

    if (params.nPercentageOfSignaturesMean < MIN_PERCENTAGE_OF_SIGNATURES_MEAN || params.nPercentageOfSignaturesMean > MAX_PERCENTAGE_OF_SIGNATURES_MEAN) {
        LogPrintf("CheckDynamicChainParameters : ERROR, %u nPercentageOfSignatureMean is out of bounds\n", params.nPercentageOfSignaturesMean);
        return false;
    }

    if (params.nMaxBlockSize < MIN_SIZE_OF_BLOCK || params.nMaxBlockSize > MAX_SIZE_OF_BLOCK) {
        LogPrintf("CheckDynamicChainParameters : ERROR, %u nMaxBlockSize is out of bounds\n", params.nMaxBlockSize);
        return false;
    }

    return true;
}

void UpdateChainParameters(const CBlock* pblock)
{
    LogPrint("cvn", "UpdateChainParameters : updating dynamic block chain parameters\n");

    if (!pblock->HasChainParameters()) {
        LogPrintf("UpdateChainParameters : ERROR, block is not of type 'chain parameter'\n");
        return;
    }

    CheckDynamicChainParameters(pblock->dynamicChainParams);

    dynParams.nBlockSpacing                = pblock->dynamicChainParams.nBlockSpacing;
    dynParams.nBlockSpacingGracePeriod     = pblock->dynamicChainParams.nBlockSpacingGracePeriod;
    dynParams.nTransactionFee              = pblock->dynamicChainParams.nTransactionFee;
    dynParams.nDustThreshold               = pblock->dynamicChainParams.nDustThreshold;
    dynParams.nMaxAdminSigs                = pblock->dynamicChainParams.nMaxAdminSigs;
    dynParams.nMinAdminSigs                = pblock->dynamicChainParams.nMinAdminSigs;
    dynParams.nMinSuccessiveSignatures     = pblock->dynamicChainParams.nMinSuccessiveSignatures;
    dynParams.nBlocksToConsiderForSigCheck = pblock->dynamicChainParams.nBlocksToConsiderForSigCheck;
    dynParams.nPercentageOfSignaturesMean  = pblock->dynamicChainParams.nPercentageOfSignaturesMean;
    dynParams.nMaxBlockSize                = pblock->dynamicChainParams.nMaxBlockSize;

    ::minRelayTxFee = CFeeRate(dynParams.nTransactionFee);
}

bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params& params)
{
    uint256 hashBlock = block.GetHash();

    if (!CvnVerifyChainSignature(block))
        return false;

    if (!mapBlockIndex.count(block.hashPrevBlock)) {
        if (hashBlock != params.hashGenesisBlock)
            LogPrint("cvn", "CheckProofOfCooperation : can not check orphan block %s created by 0x%08x, delaying check.\n",
                        hashBlock.ToString(), block.nCreatorId);
            return true; //TODO: not sure if this is good
    }

    // check if creator ID matches consensus rules
    uint32_t nBlockCreator = (hashBlock == params.hashGenesisBlock) ?
            block.nCreatorId :
            CheckNextBlockCreator(mapBlockIndex[block.hashPrevBlock], block.nTime);

    if (!nBlockCreator)
        return error("FATAL: can not determine block creator for %s", hashBlock.ToString());

    if (nBlockCreator != block.nCreatorId)
        return error("block %s can not be created by 0x%08x but by 0x%08x", hashBlock.ToString(), block.nCreatorId, nBlockCreator);

    LogPrint("cvn", "CheckProofOfCooperation : checked %u signatures of block %s created by 0x%08x\n",
            block.GetNumChainSigs(), hashBlock.ToString(), block.nCreatorId);

    return true;
}

bool CheckForDuplicateCvns(const CBlock& block)
{
    boost::unordered_set<uint32_t> sNodeIds;

    BOOST_FOREACH(const CCvnInfo &cvn, block.vCvns)
        if (!sNodeIds.insert(cvn.nNodeId).second)
            return error("detected duplicate CVN Id: 0x%08x", cvn.nNodeId);

    return true;
}

bool CheckForDuplicateChainAdmins(const CBlock& block)
{
    boost::unordered_set<uint32_t> sNodeIds;

    BOOST_FOREACH(const CChainAdmin &adm, block.vChainAdmins)
        if (!sNodeIds.insert(adm.nAdminId).second)
            return error("detected duplicate chain admin Id: 0x%08x", adm.nAdminId);

    return true;
}

typedef map<uint256, vector<CCvnInfo> > CachedCvnType;
static CachedCvnType mapChachedCVNInfoBlocks;

static uint32_t FindNewlyAddedCVN(const CBlockIndex* pindexStart)
{
    const CChainParams& chainparams = Params();

    uint32_t nLastAddedNode = 0;
    const CBlockIndex* pindexFound = NULL;

    // find the CVN that was added last
    for (const CBlockIndex* pindex = pindexStart; pindex; pindex = pindex->pprev) {
        if (pindex->nVersion & CBlock::CVN_PAYLOAD) {
            vector<CCvnInfo> vCvnInfoFromBlock;
            CachedCvnType::iterator it = mapChachedCVNInfoBlocks.find(pindex->GetBlockHash());

            if (it == mapChachedCVNInfoBlocks.end()) {
                CBlock block;
                if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus())) {
                    LogPrintf("FATAL: Failed to read block %s\n", pindex->GetBlockHash().ToString());
                    return 0;
                }
                mapChachedCVNInfoBlocks[pindex->GetBlockHash()] = block.vCvns;
                vCvnInfoFromBlock = block.vCvns;
            } else {
                vCvnInfoFromBlock = it->second;
            }

            BOOST_FOREACH(const CCvnInfo& cvn, vCvnInfoFromBlock)
            {
                if (cvn.nHeightAdded == (uint32_t)pindex->nHeight) {
                    nLastAddedNode = cvn.nNodeId;
                    pindexFound = pindex;
#if POC_DEBUG
                    LogPrintf("last added CVN: 0x%08x at height: %u\n%s\n", nLastAddedNode, pindex->nHeight, cvn.ToString());
#endif
                    break;
                }
            }

            if (nLastAddedNode)
                break;
        }
    }

    if (!nLastAddedNode || !pindexFound) // should not happen
        return 0;

    // if the last added node has created a block there is no new CVN that needs to be bootstrapped
    for (const CBlockIndex* pindex = pindexStart; pindex && pindex != pindexFound; pindex = pindex->pprev) {
        if (pindex->nCreatorId == nLastAddedNode)
            return 0;
    }

    return nLastAddedNode;
}

/* try to find a node that did not *create* a block with the
 * last POC_BLOCKS_TO_SCAN blocks but recently successively *signed* the
 * required number of last blocks. This node will then be chosen to create
 * the next block
 * */
typedef std::map<uint32_t, uint32_t> map_t;
static uint32_t FindDormantNode(const CBlockIndex* pindexStart, const map<uint32_t, uint32_t> &vLastSignatures, const TimeWeightSetType &setCreatorCandidates, const uint32_t &nMinSigs)
{
    set<uint32_t> setDormantNodes;
    BOOST_FOREACH(const map_t::value_type &signer, vLastSignatures) {
        if (!setCreatorCandidates.count(signer.first) && signer.second >= nMinSigs && !mapBannedCVNs.count(signer.first))
            setDormantNodes.insert(signer.first);
    }

    if (setDormantNodes.empty())
        return 0;

    if (setDormantNodes.size() == 1)
        return *setDormantNodes.begin();

    /* here we have the unlikely case that there is more
     * than one dormant node. The node with the highest time-weight
     * will be chosen.
     */
    for (const CBlockIndex* pindex = pindexStart; pindex; pindex = pindex->pprev) {
        if (setDormantNodes.count(pindex->nCreatorId)) {
            setDormantNodes.erase(pindex->nCreatorId);
            if (setDormantNodes.empty())
                return pindex->nCreatorId;
        }
    }

    return 0;
}

static uint32_t GetCandidateOffset(const uint64_t nPrevBlockTime, const int64_t nTimeToTest)
{
    int nOverdue = nTimeToTest - nPrevBlockTime - dynParams.nBlockSpacing;

    if (nOverdue < (int)dynParams.nBlockSpacingGracePeriod)
        return 0;

    return nOverdue / dynParams.nBlockSpacingGracePeriod;
}

#if 0
static const string CreateSignerIdList(const std::vector<uint32_t>& vMissing)
{
    std::stringstream s;

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
    {
        if (!vMissing.empty() && find(vMissing.begin(), vMissing.end(), cvn.first) != vMissing.end())
            continue;

        s << strprintf("%s%08x", (s.tellp() > 0) ? "," : "", cvn.first);
    }

    return s.str();
}
#endif

/**
 * The rules are as follows:
 * 1. If there is any newly added CVN it is its turn
 * 1. Find the node with the highest time-weight. That's the
 *    node that created its last block the furthest in the past.
 * 2. It must have co-signed the last nCreatorMinSignatures blocks
 *    to proof it's cooperation.
 */
//TODO: we should really make sure some lock is held here
uint32_t CheckNextBlockCreator(const CBlockIndex* pindexStart, const int64_t nTimeToTest, CCvnStatus* state)
{
    TimeWeightSetType setCreatorCandidates(mapCVNs.size());
    vector<uint32_t> vCreatorCandidates;
    map<uint32_t, uint32_t> mapLastSignatures; // key: signerId, value: # of sigs
    uint32_t nMinSignatures = dynParams.nMinSuccessiveSignatures;

    // create a list of creator candidates
    // scan no more than the last 200 blocks
    int nBlocksToScan = POC_BLOCKS_TO_SCAN;
    size_t nRegisteredCVNs = mapCVNs.size();
    for (const CBlockIndex* pindex = pindexStart; pindex && nBlocksToScan; pindex = pindex->pprev, nBlocksToScan--) {
        if (!mapCVNs.count(pindex->nCreatorId) || mapBannedCVNs.count(pindex->nCreatorId))
            continue; // ignore CVNs that were deactivated or banned

        // if the creator has not been considered yet add it to the list of candidates
        if (setCreatorCandidates.insert(pindex->nCreatorId).second)
            vCreatorCandidates.push_back(pindex->nCreatorId);

        // record the number of signatures within the nMinSuccessiveSignatures range
        if (nMinSignatures) {
            nMinSignatures--;
            vector<uint32_t> vMissing = pindex->vMissingCreatorIds;
            BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
            {
                if (!vMissing.empty() && find(vMissing.begin(), vMissing.end(), cvn.first) != vMissing.end())
                    continue;

                mapLastSignatures[cvn.first]++;
            }
        }

        if (vCreatorCandidates.size() == nRegisteredCVNs && !nMinSignatures)
            break; // no more work to do
    }

    uint32_t nNextCreatorId = FindNewlyAddedCVN(pindexStart);

    if (nNextCreatorId) {
        LogPrintf("CheckNextBlockCreator : CVN 0x%08x needs to be bootstrapped\n", nNextCreatorId);
        vCreatorCandidates.push_back(nNextCreatorId);
    } else if (vCreatorCandidates.size() < nRegisteredCVNs) {
        nNextCreatorId = FindDormantNode(pindexStart, mapLastSignatures, setCreatorCandidates, dynParams.nMinSuccessiveSignatures);

        if (nNextCreatorId) {
            LogPrintf("CheckNextBlockCreator : dormant CVN 0x%08x detected - activating...\n");
            vCreatorCandidates.push_back(nNextCreatorId);
        }
    }

    // the last entry in the list has the highest priority (aka. time-weight)
    CandidateIterator itCandidates = vCreatorCandidates.rbegin();

    if (!vCreatorCandidates.size()) {
        LogPrintf("CheckNextBlockCreator : ERROR, could not find any creator node candidates\n");
        return 0;
    }

    uint32_t nCandidateOffset = GetCandidateOffset(pindexStart->nTime, nTimeToTest);
    if (nCandidateOffset >= vCreatorCandidates.size()) {
        LogPrintf("CheckNextBlockCreator : WARN, CandidateOffset exceeds limits: %u >= %u\n", nCandidateOffset, vCreatorCandidates.size());
        nCandidateOffset %= vCreatorCandidates.size();
        LogPrintf("CheckNextBlockCreator : reducing offset to %u\n", nCandidateOffset);
    }

    itCandidates += nCandidateOffset;
    nMinSignatures = dynParams.nMinSuccessiveSignatures; // reset
    do {
        uint32_t nCreatorCandidate = *(itCandidates ++);

        // check if the candidate signed the last nMinSuccessiveSignatures blocks
        if (mapLastSignatures[nCreatorCandidate] >= nMinSignatures) {
            nNextCreatorId = nCreatorCandidate;
            break;
        }

        // if we did not find a candidate who signed enough blocks we lower
        // our requirement to avoid the block chain become stalled
        if (itCandidates == vCreatorCandidates.rend()) {
            itCandidates = vCreatorCandidates.rbegin();
            itCandidates += nCandidateOffset;
            nMinSignatures--;
            LogPrintf("CheckNextBlockCreator: WARN, could not find a CVN that signed enough successive blocks. Lowering number of required sigs to %u\n", nMinSignatures);
        }
    } while (nMinSignatures);

    if (!nNextCreatorId)
        LogPrintf("ERROR, could not find any node ID that should create the next block #%u\n", pindexStart->nHeight + 1);

    LogPrint("cvn", "NODE ID 0x%08x should create the next block #%u\n", nNextCreatorId, pindexStart->nHeight + 1);

    if (state) { // in case the CVNs status is requested
        state->nBlockSigned = mapLastSignatures[state->nNodeId];

        uint32_t nPredictedNextBlock = chainActive.Tip()->nHeight + 1;
        nMinSignatures = dynParams.nMinSuccessiveSignatures;
        itCandidates = vCreatorCandidates.rbegin();

        do {
            uint32_t nCreatorCandidate = *(itCandidates ++);

            if (mapLastSignatures[nCreatorCandidate] >= nMinSignatures && nCreatorCandidate == state->nNodeId)
                break;

            nPredictedNextBlock++;

            if (itCandidates == vCreatorCandidates.rend()) {
                itCandidates = vCreatorCandidates.rbegin();
                itCandidates += nCandidateOffset;
                nMinSignatures--;
            }
        } while (nMinSignatures);

        state->nPredictedNextBlock = nPredictedNextBlock;
    }

    return nNextCreatorId;
}

void POC_create_secp256k1_context()
{
    assert(secp256k1_context_none == NULL);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(ctx != NULL);

    secp256k1_context_none = ctx;
}

void POC_destroy_secp256k1_context()
{
    secp256k1_context *ctx = secp256k1_context_none;
    secp256k1_context_none = NULL;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}

uint32_t CBlockHeader::GetNumChainSigs() const {
    return mapCVNs.size() - vMissingCreatorIds.size();
}

enum SignerThreadState {
    SEND_NONCE,
    WAITING_FOR_NONCES,
    WAITING_FOR_BLOCK
};

void static CCVNSignerThread(const CChainParams& chainparams, const uint32_t& nNodeId)
{
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("CVN-signer");

    while (IsInitialBlockDownload() && !ShutdownRequested()) {
        LogPrintf("Block chain download in progress. Waiting...\n");
        MilliSleep(5000);
    }

    uint32_t nNextCreator = CheckNextBlockCreator(chainActive.Tip(), GetAdjustedTime());

    while (!nNextCreator && !ShutdownRequested()) {
        LogPrintf("Next creator ID not available. Waiting...\n");
        MilliSleep(5000);
        nNextCreator = CheckNextBlockCreator(chainActive.Tip(), GetAdjustedTime());
    }

    srand(GetTimeMillis() - nCvnNodeId);

    uint32_t nLastCreator = 0;
    CBlockIndex* pindexLastTip = chainActive.Tip();

    MilliSleep(5000);
    LogPrintf("CVN signer thread started for node ID 0x%08x\n", nNodeId);

    SignerThreadState state = WAITING_FOR_BLOCK;

    try {
        while (!ShutdownRequested()) {
            CBlockIndex* pindexPrev = chainActive.Tip();

            nNextCreator = CheckNextBlockCreator(pindexPrev, GetAdjustedTime());

            if (!nNextCreator) { // should not happen! And if it did, behave nice
                MilliSleep(2000);
                continue;
            }

            CvnNonceCreatorType& creators = mapCvnNonces[pindexPrev->GetBlockHash()];
            CvnNonceSignerType& signers = creators[nNextCreator];

            bool fNewTip = pindexLastTip != pindexPrev;

            if (nLastCreator != nNextCreator || fNewTip) {
                state = SEND_NONCE;
            }

            /*
             *  Phase 1: create nonce pair and send out the public part
             */
            if (state == SEND_NONCE) {
                if (ShutdownRequested())
                    break;

                /* randomise distribution of the CVN nonces to avoid peeks on the network
                 * and to give precedence to block propagation */
                MilliSleep((rand() % 10) * 1000);

                LogPrint("cvn", "CCVNSignerThread : sending nonce for prev block: %s\n", pindexPrev->GetBlockHash().ToString());
                SendCVNNonce(pindexPrev);
                nLastCreator = CheckNextBlockCreator(pindexPrev, GetAdjustedTime());
                pindexLastTip = pindexPrev;

                state = WAITING_FOR_NONCES;
            }

            /*
             * Phase 2: starts when we have received the nonces of all active CVNs
             */
            if (state == WAITING_FOR_NONCES) {
                /* did we receive nonces for the current tip */
                if (mapCvnNonces.count(pindexPrev->GetBlockHash())) {
                    /* did we receive nonces for the determined next creator ID */
                    if (creators.count(nNextCreator)) {
                        uint32_t nBlockTime = GetAdjustedTime() - pindexPrev->nTime;
                        bool fTimeoutWaitingForNonces = nBlockTime > dynParams.nBlockSpacing / 2 && nBlockTime < dynParams.nBlockSpacing;
                        bool fReceivedAllNonces = signers.size() == mapCVNs.size();

                        LogPrintf("WAITING_FOR_NONCES: nBlockTime: %u, timeout: %u, upper: %u\n", nBlockTime, dynParams.nBlockSpacing / 2, dynParams.nBlockSpacing);

                        if (fTimeoutWaitingForNonces)
                            LogPrintf("Timeout while waiting for nonces.\n");

                        if (signers.count(nCvnNodeId) && (fReceivedAllNonces || fTimeoutWaitingForNonces)) {
                            LogPrint("cvn", "CCVNSignerThread : sending partial signature for prev block: %s\n", pindexPrev->GetBlockHash().ToString());
                            SendCVNSignature(pindexPrev);
                            state = WAITING_FOR_BLOCK;
                        }
                    }
                }
            }

            MilliSleep(1000);
        }

        LogPrintf("CVN signer thread stopped\n");
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("CVN signer thread terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("CCVNSignerThread runtime error: %s\n", e.what());
        return;
    }
}

void RunCVNSignerThread(const bool fGenerate, const CChainParams& chainparams, const uint32_t& nNodeId)
{
    static boost::thread_group* signerThreads = NULL;

    if (signerThreads != NULL)
    {
        signerThreads->interrupt_all();
        delete signerThreads;
        signerThreads = NULL;

        return;
    }

    if (!fGenerate)
        return;

    if (!nNodeId) {
        LogPrintf("Not starting CVN signer thread. CVN not configured.\n");
        return;
    }

    signerThreads = new boost::thread_group();
    signerThreads->create_thread(boost::bind(&CCVNSignerThread, boost::cref(chainparams), boost::cref(nNodeId)));
}
