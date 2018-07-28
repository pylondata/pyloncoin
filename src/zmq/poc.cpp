// Copyright (c) 2016-2017 The Pyloncoin Core developers
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
#include "init.h"
#include "fasito/cert.h"
#include "clientversion.h"
#include "validationinterface.h"
#include "blockfactory.h"

#ifdef USE_FASITO
#include "fasito/fasito.h"
#endif

#include <secp256k1.h>
#include <secp256k1_schnorr.h>
#include <boost/thread.hpp>
#include <stdio.h>
#include <set>

// changing this is a consensus change
#define POC_BLOCKS_TO_SCAN 200

#define POC_DEBUG 0

uint32_t nCvnNodeId = 0;
uint32_t nChainAdminId = 0;
bool fNoncePoolInitialsed = false;
bool fCoinSupplyFinal = false;

CvnInfoCacheType mapCVNInfoCache;
CachedCvnType mapChachedCVNInfoBlocks;

CCriticalSection cs_mapChainAdmins;
ChainAdminMapType mapChainAdmins;

CCriticalSection cs_mapCVNs;
CvnMapType mapCVNs;

CCriticalSection cs_mapNoncePool;
CNoncePoolType mapNoncePool;
CNoncePoolType mapNoncePoolCheckLater;

CCriticalSection cs_mapChainData;
ChainDataMapType mapChainData;

CCriticalSection cs_mapBlockIndexByPrevHash;
BlockIndexByPrevHashType mapBlockIndexByPrevHash;

CCriticalSection cs_mapBannedCVNs;
BannedCVNMapType mapBannedCVNs;

CCriticalSection cs_mapAdminNonces;
CNoncesMapType mapAdminNonces;

CCriticalSection cs_mapAdminSigs;
MapSigAdmin mapAdminSigs;

/* private nonces when starting pyloncoind with -cvn=file */
static vector<CSchnorrPrivNonce> vNoncePrivate;
static secp256k1_context *secp256k1_context_none = NULL;

bool static CvnSignPartialWithKey(const uint256& hashToSign, const CKey& cvnPrivKey, const CSchnorrPubKey& sumPublicNoncesOthers, CSchnorrSig& signature, const int nPoolOffset);

const char *pocStateNames[] = {
        "INIT",
        "WAITING_FOR_BLOCK_PROPAGATION",
        "CREATE_SIGNATURE",
        "WAITING_FOR_SIGNATURES",
        "WAITING_FOR_BLOCK",
        "WAITING_FOR_NEW_TIP",
        "WAITING_FOR_CVN_DATA",
        "COMPLETE_SIGNATURE_SETS",
        "CREATE_SIGNATURE_OVERDUE",
        "WAITING_FOR_SIGNATURES_OVERDUE",
        "UNDEFINED",
};

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
        cout << "\n";
}
#endif

bool AddToCvnInfoCache(const CBlock *pblock, const uint32_t nHeight)
{
    if (!pblock->HasCvnInfo())
        return false;

    LOCK(cs_mapCVNs);

    mapCVNs.clear();
    int count = 0;
    secp256k1_pubkey *allSignersPubkeys[MAX_NUMBER_OF_CVNS];

    BOOST_FOREACH(const CCvnInfo &cvnInfo, pblock->vCvns) {
        mapCVNs.insert(std::make_pair(cvnInfo.nNodeId, cvnInfo));
        allSignersPubkeys[count++] = (secp256k1_pubkey *)&cvnInfo.pubKey.begin()[0];
    }

    secp256k1_pubkey sumOfAllSignersPubkeys;
    if (count == 1) {
        memcpy(sumOfAllSignersPubkeys.data, &pblock->vCvns[0].pubKey.begin()[0], 64);
    } else {
        if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, &sumOfAllSignersPubkeys, allSignersPubkeys, count))
            return error("%s : could not combine signers public keys", __func__);
    }

    mapCVNInfoCache[nHeight] = CvnInfoCache(sumOfAllSignersPubkeys, mapCVNs.size());
    return true;
}

static bool GetCvnInfoCache(CvnInfoCache **cache, const uint32_t nHeight)
{
    if (mapCVNInfoCache.empty()) {
        LogPrintf("%s : fatal, CVN info cache is empty\n", __func__);
        return false;
    }

    if (!nHeight) { // genesis block
        *cache = &mapCVNInfoCache[0];
        return true;
    }

    CvnInfoCacheType::reverse_iterator it = mapCVNInfoCache.rbegin();

    while (it != mapCVNInfoCache.rend()) {
        if (it->first < nHeight) {
            *cache = &it->second;
            return true;
        }
        it++;
    }

    return false;
}

uint32_t GetNumChainSigs(const CBlockIndex *pindex)
{
    CvnInfoCache *info;
    if (!GetCvnInfoCache(&info, pindex->nHeight)) {
        LogPrintf("%s : could not find CVN information\n", __func__);
        return 0;
    }

    return info->nActiveCvns - pindex->vMissingSignerIds.size();
}

uint32_t GetNumChainSigs(const CBlock *pblock)
{
    BlockMap::iterator miPrev = mapBlockIndex.find(pblock->hashPrevBlock);
    if (miPrev == mapBlockIndex.end()) {
        LogPrintf("%s : prev block not found in block index: %s\n", __func__, pblock->hashPrevBlock.ToString());
        return 0;
    }

    CBlockIndex *pindexPrev = (*miPrev).second;
    CvnInfoCache *info;
    if (!GetCvnInfoCache(&info, pindexPrev->nHeight + 1)) {
        LogPrintf("%s : could not find CVN information\n", __func__);
        return 0;
    }

    return info->nActiveCvns - pblock->vMissingSignerIds.size();
}

const string CreateSignerIdList(const std::vector<uint32_t>& vNodeIds)
{
    std::stringstream s;

    if (vNodeIds.empty())
        return "none";

    BOOST_FOREACH(const uint32_t& id, vNodeIds)
    {
        s << strprintf("%s0x%08x", (s.tellp() > 0) ? "," : "", id);
    }

    return s.str();
}

void CvnInfoCache::SetNull()
{
    nActiveCvns = 0;
    memset(sumOfAllpubKeys.data, 0, sizeof(sumOfAllpubKeys.data));
}

void CSignatureHolder::AddSig(const CCvnPartialSignature &sig)
{
    LOCK(cs_sigHolder);

    MapSigSigner& mapSigner   = sigs[sig.signature.GetRx()];

    mapSigner[sig.nSignerId]  = sig;
}

MapSigSigner* CSignatureHolder::GetSignatureSet(const CSchnorrRx &commonRx)
{
    LOCK(cs_sigHolder);

    if (!sigs.count(commonRx))
        return NULL;

    return &sigs[commonRx];
}

CCvnPartialSignature* CSignatureHolder::GetSignature(const uint32_t nSignerId, const CSchnorrRx &commonRx)
{
    if (!sigs.count(commonRx))
        return NULL;

    MapSigSigner& mapSigner = sigs[commonRx];

    if (!mapSigner.count(nSignerId))
        return NULL;

    return &mapSigner[nSignerId];
}

bool CSignatureHolder::GetSignatures(vector<CCvnPartialSignature> &vSigs)
{
    LOCK(cs_sigHolder);

    if (sigs.empty())
        return false;

    MapSigSigner& mapSigner = sigs.begin()->second;
    if (mapSigner.empty())
        return false;

    BOOST_FOREACH(const MapSigCommonR::value_type &entry, sigs) {
        BOOST_FOREACH(const MapSigSigner::value_type &s, entry.second) {
            vSigs.push_back(s.second);
        }
    }

    return !vSigs.empty();
}

bool CSignatureHolder::HasSigSetsToContributeTo(vector<vector<uint32_t> > &vSigSetsToContributeTo, const uint32_t nNodeId, const uint32_t nActiveCVNs)
{
    LOCK(sigHolder.cs_sigHolder);

    if (sigs.empty())
        return false;

    BOOST_FOREACH(const MapSigCommonR::value_type &entry, sigs) {
        const MapSigSigner &s = entry.second;
        const CCvnPartialSignature &sigFirst = s.begin()->second;

        if (s.empty() || (nActiveCVNs - sigFirst.vMissingSignerIds.size()) == s.size())
            continue;

        if (s.find(nNodeId) == s.end()) {
            vSigSetsToContributeTo.push_back(sigFirst.vMissingSignerIds);
        }
    }

    return !vSigSetsToContributeTo.empty();
}

bool CSignatureHolder::HasCompleteSigSets(const uint32_t nMaxSignatures) const
{
    LOCK(sigHolder.cs_sigHolder);

    if (sigs.empty())
        return false;

    BOOST_FOREACH(const MapSigCommonR::value_type &entry, sigs) {
        const MapSigSigner &s = entry.second;
        if (s.empty())
            continue;

        const CCvnPartialSignature &sigFirst = s.begin()->second;

        if ((nMaxSignatures - sigFirst.vMissingSignerIds.size()) == s.size()) {
            return true;
        }
    }

    return false;
}

/**
 * Get all the missing CVN Ids that failed to co-sign any of the signature sets.
 *
 * Iterate over all commonRxs we've received so far and find out which CVN
 * did not manage to create a signature for the set and sum it up.
 *
 * The node IDs in vMissingSignerIds are considered to be offline.
 */
bool CSignatureHolder::GetAllMissing(vector<uint32_t> &vMissingSignerIds, const uint32_t nNodeId, const vector<CSchnorrRx> &commonRxs, const CNoncePoolType &mapNoncePool, const uint32_t nActiveCVNs)
{
    LOCK(sigHolder.cs_sigHolder);

    if (sigs.empty())
        return false;

    set<uint32_t> sMissing;

    BOOST_FOREACH(const CSchnorrRx &commonRx, commonRxs) {
        if (sigs.find(commonRx) == sigs.end())
            continue;

        const MapSigSigner &s = sigs[commonRx];

        if (s.empty())
            continue;

        const CCvnPartialSignature &sigFirst = s.begin()->second;

        if (nActiveCVNs - sigFirst.vMissingSignerIds.size() == s.size())
            continue; // no missing IDs for this commonR

        BOOST_FOREACH(const CNoncePoolType::value_type& p, mapNoncePool) {
            if (s.find(p.first) != s.end())
                continue;

            sMissing.insert(p.first);
        }
    }

    if (sMissing.empty())
        return false;

    vMissingSignerIds.resize(sMissing.size());
    copy(sMissing.begin(), sMissing.end(), vMissingSignerIds.begin());
    return true;
}

void CSignatureHolder::clear(const uint32_t nNextCreator)
{
    LOCK(cs_sigHolder);

    MapSigCommonR::iterator ci = sigs.begin();

    while(ci != sigs.end()) {
        MapSigSigner &m = ci->second;
        MapSigSigner::iterator mi = m.begin();

        while(mi != m.end()) {
            const CCvnPartialSignature& sig = mi->second;
            if (sig.nCreatorId != nNextCreator) {
                m.erase(mi++);
            } else {
                ++mi;
            }
        }

        if (m.empty()) {
            sigs.erase(ci++);
        } else {
            ++ci;
        }
    }
}

string CSignatureHolder::ToString()
{
    std::stringstream s;

    LOCK(cs_sigHolder);
    BOOST_FOREACH(const MapSigCommonR::value_type& commonRx, sigs) {
        s << strprintf("commonRx    (%02d): %s\n", commonRx.second.size(), commonRx.first.ToString());
        BOOST_FOREACH(const MapSigSigner::value_type& signer, commonRx.second) {
            s << strprintf(" signer         : 0x%08x (%s)\n", signer.first, signer.second.ToString());
        }
    }

    return s.str();
}

CSignatureHolder sigHolder;

static bool CreateSumPublicAdminNoncesOthers(CSchnorrPubKey &sumPublicNoncesOthers, const uint32_t nAdminId, vector<uint32_t> &vAdminIds)
{
    LOCK(cs_mapNoncePool);
    vector<secp256k1_pubkey *> allPubOtherNonces;

    BOOST_FOREACH(const ChainAdminMapType::value_type& admin, mapChainAdmins) {
        if (mapAdminNonces.find(admin.first) == mapAdminNonces.end())
            continue;

        vAdminIds.push_back(admin.first);

        if (admin.first == nAdminId)
            continue;

        LogPrint("cvn", "%s : adding 0x%08x\n", __func__, admin.first);

        const CSchnorrNonce *nonce = &mapAdminNonces[admin.first];
        allPubOtherNonces.push_back((secp256k1_pubkey *)nonce);
    }

    memset(&sumPublicNoncesOthers.begin()[0], 0, 64);
    if (allPubOtherNonces.size() > 1) {
        if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, (secp256k1_pubkey *)&sumPublicNoncesOthers.begin()[0], &allPubOtherNonces[0], allPubOtherNonces.size())) {
            LogPrintf("%s : could not combine nonces\n", __func__);
            return false;
        }
    } else if (allPubOtherNonces.size() == 1) {
        memcpy(&sumPublicNoncesOthers.begin()[0], allPubOtherNonces[0], 64);
    } else {
        LogPrintf("%s : no nonces avaialbe\n", __func__);
        return false;
    }

    return true;
}

const CSchnorrNonce *GetCurrnetPublicNonce(const uint32_t nNodeId)
{
    if (!mapNoncePool.count(nNodeId)) {
        LogPrintf("GetCurrnetPublicNonce : could not find nonce pool for CvnID 0x%08x\n");
        return NULL;
    }

    const CNoncePool &pool = mapNoncePool[nNodeId];

    uint32_t nHeight = chainActive.Tip()->nHeight;
    int nPoolOffset = nHeight - pool.nHeightAdded;

    if (nPoolOffset < 0) {
        LogPrintf("GetCurrnetPublicNonce : invalid pool offset, CVN 0x%08x, offset: %d\n", nNodeId, nPoolOffset);
        return NULL;
    }

    if (nPoolOffset >= (int)pool.vPublicNonces.size()) {
        LogPrintf("GetCurrnetPublicNonce : pool too old, CVN 0x%08x, offset: %d, size: %d\n", nNodeId, nPoolOffset, pool.vPublicNonces.size());
        return NULL;
    }

    return &pool.vPublicNonces[nPoolOffset];
}

bool CreateSumPublicNoncesOthers(CSchnorrPubKey &sumPublicNoncesOthers, const uint32_t& nNextCreator, const uint32_t& nNodeId, const vector<uint32_t> &vMissingSignerIds)
{
    LOCK(cs_mapNoncePool);
    vector<secp256k1_pubkey *> allPubOtherNonces;

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs) {
        if (cvn.first == nNodeId)
            continue;

        if (find(vMissingSignerIds.begin(), vMissingSignerIds.end(), cvn.first) != vMissingSignerIds.end()) {
            continue;
        }

        if (mapNoncePool.find(cvn.first) == mapNoncePool.end()) {
            LogPrintf("%s : nonce pool unavailable for 0x%08x\n", __func__, cvn.first);
            return false;;
        }

        const CSchnorrNonce *nonce = GetCurrnetPublicNonce(cvn.first);
        if (nonce == NULL)
            continue;

        allPubOtherNonces.push_back((secp256k1_pubkey *)nonce);
    }

    LogPrint("cvn", "%s : %s are missing\n", __func__, CreateSignerIdList(vMissingSignerIds));

    memset(&sumPublicNoncesOthers.begin()[0], 0, 64);
    if (allPubOtherNonces.size() > 1) {
        if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, (secp256k1_pubkey *)&sumPublicNoncesOthers.begin()[0], &allPubOtherNonces[0], allPubOtherNonces.size())) {
            LogPrintf("%s : could not combine nonces\n", __func__);
            return false;
        }
    } else if (allPubOtherNonces.size() == 1) {
        memcpy(&sumPublicNoncesOthers.begin()[0], allPubOtherNonces[0], 64);
    } else {
        LogPrintf("%s : no nonces avaialbe\n", __func__);
        return false;
    }

    return true;
}

bool VerifyNoncePoolEntry(const int &nPoolOffset)
{
    CHashWriter hasher(SER_GETHASH, 0);

    if (!nCvnNodeId) {
        LogPrintf("%s : CVN node not initialised\n", __func__);
        return false;
    }

    CvnMapType::iterator cvnInfoIter = mapCVNs.find(nCvnNodeId);

    if (cvnInfoIter == mapCVNs.end()) {
        LogPrintf("%s : # %d could not find CvnInfo for signer ID 0x%08x\n", __func__, nPoolOffset, nCvnNodeId);
        return false;
    }

    CSchnorrPubKey dummySumPublicNoncesOthers = cvnInfoIter->second.pubKey;
    hasher << dummySumPublicNoncesOthers;

    uint256 hashToSign = hasher.GetHash();
    CSchnorrSig signature;

    if (GetArg("-cvn", "") == "fasito") {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrint("cvn", "%s : not logged into Fasito. Cannot create partial signature.\n", __func__);
            return false;
        }

        if (!CvnSignPartialWithFasito(hashToSign, fasito.nCVNKeyIndex, dummySumPublicNoncesOthers, signature, nPoolOffset))
            return false;
#else
        LogPrintf("%s : this wallet was not compiled with Fasito support.\n", __func__);
        return false;
#endif
    } else {
        if (!CvnSignPartialWithKey(hashToSign, cvnPrivKey, dummySumPublicNoncesOthers, signature, nPoolOffset))
            return false;
    }

    return VerifyPartialSignature(hashToSign, signature, dummySumPublicNoncesOthers, dummySumPublicNoncesOthers);
}

static void UpdateHashWithMissingIDs(CHashWriter &hasher, const vector<uint32_t> &vMissingSignerIds)
{
    if (vMissingSignerIds.empty())
        return;

    /* if we have missing signers we modify the hashToSign to avoid that
     * that we sign the same message with a different set of nonces
     *
     * We sum up all the nMisingIds in nSumNodeIds so the
     * order of the IDs doesn't matter */

    uint64_t nSumNodeIds = 0;

    BOOST_FOREACH(const uint32_t& nMissingId, vMissingSignerIds) {
        nSumNodeIds += nMissingId;
    }

    hasher << nSumNodeIds;
}

bool CvnVerifyChainSignature(const CBlock& block)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << block.hashPrevBlock << block.nCreatorId;

    /* special case when bootstrapping the blockchain we only have one CVN ID */
    if (mapCVNs.size() == 1) {
        if (!mapCVNs.count(block.nCreatorId)) {
            LogPrintf("CvnVerifyChainSignature : could not find CvnInfo for signer ID 0x%08x\n", block.nCreatorId);
            return false;
        }

        if (!CPubKey::VerifySchnorr(hasher.GetHash(), block.chainMultiSig, mapCVNs[block.nCreatorId].pubKey)) {
            LogPrintf("CvnVerifyChainSignature : could not verify single sig %s for hash %s for node Id 0x%08x\n", block.chainMultiSig.ToString(), hasher.GetHash().ToString(), block.nCreatorId);
            return false;
        } else {
            return true;
        }
    }

    const vector<uint32_t>& vMissingSignersIds = block.vMissingSignerIds;
    secp256k1_pubkey sumOfAllSignersPubkeys;

    /* if there are no missing signatures we can use the cached
     * combined pubkeys from the CvnInfoCache, otherwise we combine
     * them
     */
    if (vMissingSignersIds.empty()) {
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return error("could not find block in index");

        CvnInfoCache *cache;
        GetCvnInfoCache(&cache, (*mi).second->nHeight + 1);
        sumOfAllSignersPubkeys = cache->sumOfAllpubKeys;
    } else {
        int count = 0;
        secp256k1_pubkey *allSignersPubkeys[MAX_NUMBER_OF_CVNS];

        BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
        {
            if (!vMissingSignersIds.empty() && find(vMissingSignersIds.begin(), vMissingSignersIds.end(), cvn.first) != vMissingSignersIds.end())
                continue;

            allSignersPubkeys[count++] = (secp256k1_pubkey *)&cvn.second.pubKey.begin()[0];
        }

        if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, &sumOfAllSignersPubkeys, allSignersPubkeys, count))
            return error("CvnVerifyChainSignature : could not combine signers public keys");

        UpdateHashWithMissingIDs(hasher, vMissingSignersIds);
    }

    uint256 hash = hasher.GetHash();

    CSchnorrPubKey pubKey(sumOfAllSignersPubkeys.data);
    if (!CvnVerifySignature(hash, block.chainMultiSig, pubKey))
        return error("CvnVerifyChainSignature : could not verify chain signature for block: %s sig: %s missing: %s)", hash.ToString(), block.chainMultiSig.ToString(), CreateSignerIdList(block.vMissingSignerIds));

    return true;
}

bool CvnVerifySignature(const uint256 &hash, const CSchnorrSig &sig, const CSchnorrPubKey &pubKey)
{
    if (!CPubKey::VerifySchnorr(hash, sig, pubKey))
        return false;

    return true;
}

bool VerifyPartialSignature(const uint256 &hash, const CSchnorrSig &sig, const CSchnorrPubKey &pubKey, const CSchnorrPubKey &sumPublicNoncesOthers)
{
    if (!CPubKey::VerifyPartialSchnorr(hash, sig, pubKey, sumPublicNoncesOthers)) {
        LogPrintf("CvnVerifyPartialSignature : could not verify signature!\nhash: %s\nsig: %s\npubKey: %s\nsumNonces: %s\n", hash.ToString(), sig.ToString(), pubKey.ToString(), sumPublicNoncesOthers.ToString());
        return false;
    }

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

bool VerifyAdminSignature(const uint256 &hash, const CSchnorrSig &sig, const uint32_t nAdminId)
{
    if (!mapChainAdmins.count(nAdminId)) {
        LogPrintf("ERROR: could not find chain admin for signer ID 0x%08x\n", nAdminId);
        return false;
    }

    if (!CvnVerifySignature(hash, sig, mapChainAdmins[nAdminId].pubKey)) {
        LogPrintf("could not verify sig %s for hash %s for admin Id 0x%08x\n", sig.ToString(), hash.ToString(), nAdminId);
        return false;
    }

    return true;
}

bool CvnVerifyAdminSignature(const vector<uint32_t> &vAdminIds, const uint256& hashAdmin, const CSchnorrSig& sig)
{
    if (vAdminIds.empty()) {
        LogPrintf("%s : no admin IDs avaialbe for hash: %s\n", __func__, hashAdmin.ToString());
        return false;
    }

    /* special case when bootstrapping the blockchain we have one chain admin ID only */
    if (mapChainAdmins.size() == 1) {
        const uint32_t nAdminId = mapChainAdmins.begin()->first;
        if (!mapChainAdmins.count(nAdminId)) {
            LogPrintf("%s : could not find CChainAdmin for admin ID 0x%08x\n", __func__, nAdminId);
            return false;
        }

        if (!CPubKey::VerifySchnorr(hashAdmin, sig, mapChainAdmins[nAdminId].pubKey)) {
            LogPrintf("%s : could not verify single sig %s for hash %s for admin Id 0x%08x (%s)\n", __func__, sig.ToString(), hashAdmin.ToString(), nAdminId, mapChainAdmins[nAdminId].pubKey.ToString());
            return false;
        } else {
            return true;
        }
    }

    int count = 0;
    secp256k1_pubkey *allSignersPubkeys[MAX_NUMBER_OF_CHAIN_ADMINS];

    // TODO: we should really cache this...
    BOOST_FOREACH(const ChainAdminMapType::value_type& entry, mapChainAdmins)
    {
        if (find(vAdminIds.begin(), vAdminIds.end(), entry.first) == vAdminIds.end())
            continue;

        allSignersPubkeys[count++] = (secp256k1_pubkey *)entry.second.pubKey.begin();
    }

    secp256k1_pubkey sumOfAllSignersPubkeys;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, &sumOfAllSignersPubkeys, allSignersPubkeys, count))
        return error("could not combine admin signers public keys");

    CSchnorrPubKey pubKey(sumOfAllSignersPubkeys.data);
    if (!CvnVerifySignature(hashAdmin, sig, pubKey))
        return error("could not verify admin signature: %s", hashAdmin.ToString());

    return true;
}

void RelayChainData(const CChainDataMsg& msg)
{
    CInv inv(MSG_POC_CHAIN_DATA, msg.GetHash());
    {
        LOCK(cs_mapRelayChainData);
        mapRelayChainData.insert(std::make_pair(inv.hash, msg));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayPoCMessages)
            continue;
        pnode->PushInventory(inv);
    }
}

bool CheckAdminSignature(const vector<uint32_t> &vAdminIds, const uint256 &hashAdmin, const CSchnorrSig &sig, const bool fCoinSupply)
{
    const uint32_t nSigs = vAdminIds.size();

    if (nSigs < dynParams.nMinAdminSigs) {
        LogPrintf("%s : not enough admin signatures supplied (got %u signatures, but need at least %u to sign)\n", __func__, nSigs, dynParams.nMinAdminSigs);
        return false;
    }

    if (nSigs > dynParams.nMaxAdminSigs) {
        LogPrintf("%s : too many admin signatures supplied %u (%u max)\n", __func__, nSigs, dynParams.nMaxAdminSigs);
        return false;
    }

    if (fCoinSupply && nSigs < mapChainAdmins.size()) {
        LogPrintf("%s : not enough admin signatures supplied (got %u signatures, but need at least %u to sign for coin supply)\n", __func__,
            nSigs, mapChainAdmins.size());
        return false;
    }

    return CvnVerifyAdminSignature(vAdminIds, hashAdmin, sig);
}

bool AddChainData(const CChainDataMsg& msg)
{
    if (!CheckAdminSignature(msg.vAdminIds, msg.GetHash(), msg.adminMultiSig, msg.HasCoinSupplyPayload()))
        return false;

    if (msg.HasCoinSupplyPayload() && fCoinSupplyFinal) {
        LogPrintf("%s : coin supply is already final. Ignoring chain data message.", __func__);
        return false;
    }

    const uint256 &hashBlock = msg.hashPrevBlock;

    if (!msg.HasFlushSigholderPayload()) {
        LOCK(cs_mapChainData);
        if (mapChainData.count(hashBlock)) {
            LogPrintf("received duplicate chain data for block %s: %s\n", hashBlock.ToString(), msg.ToString());
            return false;
        }

        mapChainData.insert(std::make_pair(hashBlock, msg));

        LogPrintf("%s : signed by %u (minimum %u) admins of %u/%u to be added after blockHash %s\n", __func__,
                msg.vAdminIds.size(), dynParams.nMinAdminSigs, mapChainAdmins.size(), dynParams.nMaxAdminSigs, hashBlock.ToString());
    } else if(msg.nPayload & CChainDataMsg::BLOCK_PAYLOAD_MASK) {
        LogPrintf("%s : cannot mix FLUSH payload with any other payload, ignoring...\n", __func__);
        return false;
    } else {
        LogPrintf("%s : flushing all entries from sigHolder due to admins request.\n", __func__);
        sigHolder.SetNull();
    }

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

void RelayCvnSignature(const CCvnPartialSignature& msg)
{
    CInv inv(MSG_CVN_SIGNATURE, msg.GetHash());
    {
        LOCK(cs_mapRelaySigs);
        mapRelaySigs.insert(std::make_pair(inv.hash, msg));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayPoCMessages)
            continue;
        pnode->PushInventory(inv);
    }
}

bool CvnVerifyPartialSignature(const CCvnPartialSignature& sig)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << sig.hashPrevBlock << sig.nCreatorId;

    if (!mapCVNs.count(sig.nCreatorId)) {
        LogPrintf("%s : next creator CVN not found 0x%08x\n", sig.nCreatorId, __func__);
        return false;
    }

    if (!mapCVNs.count(sig.nSignerId)) {
        LogPrintf("%s : signer CVN not found 0x%08x\n", __func__, sig.nSignerId);
        return false;
    }

    if (mapCVNs.size() == 1)
        return CvnVerifySignature(hasher.GetHash(), sig.signature, sig.nSignerId);

    CSchnorrPubKey sumPublicNoncesOthers;
    if (!CreateSumPublicNoncesOthers(sumPublicNoncesOthers, sig.nCreatorId, sig.nSignerId, sig.vMissingSignerIds))
        return false;

    UpdateHashWithMissingIDs(hasher, sig.vMissingSignerIds);

    return VerifyPartialSignature(hasher.GetHash(), sig.signature, mapCVNs[sig.nSignerId].pubKey, sumPublicNoncesOthers);
}

bool VerifyPartialAdminSignature(const CAdminPartialSignature& sig, const uint256 hash2Sign)
{
    if (!mapChainAdmins.count(sig.nAdminId)) {
        LogPrintf("%s : signer admin not found 0x%08x\n", __func__, sig.nAdminId);
        return false;
    }

    if (mapChainAdmins.size() == 1)
        return VerifyAdminSignature(hash2Sign, sig.signature, sig.nAdminId);

    CSchnorrPubKey sumPublicNoncesOthers;
    vector<uint32_t> vAdminIds;
    if (!CreateSumPublicAdminNoncesOthers(sumPublicNoncesOthers, sig.nAdminId, vAdminIds))
        return false;

    if (vAdminIds != sig.vSignerIds){
        LogPrintf("%s : admin IDs mismatch: %s (%d != %d)\n", __func__, sig.ToString(), vAdminIds.size(), sig.vSignerIds.size());
        return false;
    }

    return VerifyPartialSignature(hash2Sign, sig.signature, mapChainAdmins[sig.nAdminId].pubKey, sumPublicNoncesOthers);
}

bool AddCvnSignature(CCvnPartialSignature& msg)
{
    if (!CvnVerifySignature(msg.GetHash(), msg.msgSig, msg.nSignerId))
        return false;

    msg.fValidated = CvnVerifyPartialSignature(msg);
    if (!msg.fValidated)
        LogPrintf("%s : invalid signature received for 0x%08x by 0x%08x, hash %s. Marked as invalid.\n", __func__, msg.nCreatorId, msg.nSignerId, msg.hashPrevBlock.ToString());

    sigHolder.AddSig(msg);

    LogPrint("cvnsig", "%s : add sig for 0x%08x by 0x%08x, hash %s, missing: %s\n", __func__, msg.nCreatorId, msg.nSignerId,
            msg.hashPrevBlock.ToString(),
            (msg.vMissingSignerIds.empty() ? "none" : CreateSignerIdList(msg.vMissingSignerIds)));

    return true;
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

void UpdateCvnInfo(const CBlock* pblock, const uint32_t nHeight)
{
    LogPrint("cvn", "UpdateCvnInfo : updating CVN data at height %d\n", nHeight);

    if (!pblock->HasCvnInfo()) {
        LogPrint("cvn", "UpdateCvnInfo : ERROR, block is not of type CVN\n");
        return;
    }

    AddToCvnInfoCache(pblock, nHeight);
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

    BOOST_FOREACH(const CChainAdmin &admin, pblock->vChainAdmins) {
        mapChainAdmins.insert(std::make_pair(admin.nAdminId, admin));
    }

    PrintAllChainAdmins();
}

void SetCoinSupplyStatus(const CBlock* pblock)
{
    if (fCoinSupplyFinal)
        return;

    if (pblock->coinSupply.fFinalCoinsSupply) {
        fCoinSupplyFinal = true;
        LogPrintf("Setting coins supply status to FINAL. No more coin supply chain data is accepted in the future.\n");
    } else {
        LogPrint("cvn", "found non final coins supply: %s\n", pblock->coinSupply.ToString());
    }
}

bool CheckDynamicChainParameters(const CDynamicChainParams& params)
{
    if (params.nBlockSpacing > MAX_BLOCK_SPACING || params.nBlockSpacing < MIN_BLOCK_SPACING) {
        LogPrintf("%s : block spacing %u exceeds limit\n",__func__ , params.nBlockSpacing);
        return false;
    }

    if (params.nTransactionFee > MAX_TX_FEE_THRESHOLD || params.nTransactionFee < MIN_TX_FEE_THRESHOLD) {
        LogPrintf("%s : tx fee threshold %u exceeds limit\n",__func__ , params.nTransactionFee);
        return false;
    }

    if (params.nDustThreshold > MAX_DUST_THRESHOLD || params.nDustThreshold < MIN_DUST_THRESHOLD) {
        LogPrintf("%s : dust threshold %u exceeds limit\n",__func__ , params.nDustThreshold);
        return false;
    }

    if (!params.nMinAdminSigs || params.nMinAdminSigs > params.nMaxAdminSigs) {
        LogPrintf("%s : number of CVN signers %u/%u exceeds limit\n",__func__ , params.nMinAdminSigs, params.nMaxAdminSigs);
        return false;
    }

    if (params.nBlocksToConsiderForSigCheck < MIN_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK || params.nBlocksToConsiderForSigCheck > MAX_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK) {
        LogPrintf("%s : %u blocksToConsiderForSigCheck is out of bounds\n",__func__ , params.nBlocksToConsiderForSigCheck);
        return false;
    }

    if (params.nPercentageOfSignaturesMean < MIN_PERCENTAGE_OF_SIGNATURES_MEAN || params.nPercentageOfSignaturesMean > MAX_PERCENTAGE_OF_SIGNATURES_MEAN) {
        LogPrintf("%s : %u nPercentageOfSignatureMean is out of bounds\n",__func__ , params.nPercentageOfSignaturesMean);
        return false;
    }

    if (params.nMaxBlockSize < MIN_SIZE_OF_BLOCK || params.nMaxBlockSize > MAX_SIZE_OF_BLOCK) {
        LogPrintf("%s : %u nMaxBlockSize is out of bounds\n",__func__ , params.nMaxBlockSize);
        return false;
    }

    if (params.nBlockPropagationWaitTime < MIN_BLOCK_PROPAGATION_WAIT_TIME || params.nBlockPropagationWaitTime > MAX_BLOCK_PROPAGATION_WAIT_TIME ||
            params.nBlockPropagationWaitTime >= params.nBlockSpacing) {
        LogPrintf("%s : %u nBlockPropagationWaitTime is out of bounds\n",__func__ , params.nBlockPropagationWaitTime);
        return false;
    }

    if (params.nRetryNewSigSetInterval < MIN_RETRY_NEW_SIG_SET_INTERVAL || params.nRetryNewSigSetInterval > MAX_RETRY_NEW_SIG_SET_INTERVAL) {
        LogPrintf("%s : %u nRetryNewSigSetInterval is out of bounds\n",__func__ , params.nRetryNewSigSetInterval);
        return false;
    }

    if (params.nCoinbaseMaturity < MIN_COINBASE_MATURITY || params.nCoinbaseMaturity > MAX_COINBASE_MATURITY) {
        LogPrintf("%s : %u nCoinbaseMaturity is out of bounds\n",__func__ , params.nCoinbaseMaturity);
        return false;
    }

    if (params.strDescription.length() <= MIN_CHAIN_DATA_DESCRIPTION_LEN) {
        LogPrintf("%s : chain data description is too short: %s\n",__func__ , params.strDescription);
        return false;
    }

    return true;
}

void UpdateChainParameters(const CBlock* pblock)
{
    LogPrint("cvn", "UpdateChainParameters : updating dynamic block chain parameters\n");

    if (!pblock->HasChainParameters()) {
        LogPrintf("UpdateChainParameters : block is not of type 'chain parameter'\n");
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
    dynParams.nBlockPropagationWaitTime    = pblock->dynamicChainParams.nBlockPropagationWaitTime;
    dynParams.nRetryNewSigSetInterval      = pblock->dynamicChainParams.nRetryNewSigSetInterval;
    dynParams.nCoinbaseMaturity            = pblock->dynamicChainParams.nCoinbaseMaturity;
    dynParams.strDescription               = pblock->dynamicChainParams.strDescription;

    ::minRelayTxFee = CFeeRate(dynParams.nTransactionFee);
}

bool CheckProofOfCooperation(const CBlock& block, const Consensus::Params& params)
{
    const uint256 hashBlock = block.GetHash();

    if (!CheckForDuplicateMissingChainSigs(block))
        return false;

    BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
    if (mi == mapBlockIndex.end()) {
        if (hashBlock != params.hashGenesisBlock) {
            LogPrintf("%s : can not check orphan block %s created by 0x%08x, delaying check.\n", __func__,
                        hashBlock.ToString(), block.nCreatorId);
            return false;
        } else
            return true;
    }

    CBlockIndex * const pindexPrev = (*mi).second;
    /* during parallel blockchain download we might see only parts of the chain. These are put together at a later time.
     * In this case we do not have enough information to reliably process PoC checks. They only work on a continuous chain. */
    if ((pindexPrev->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) {
        LogPrint("cvn", "%s : can only determine next block creator for block %s if chain is valid, delaying this check.\n", __func__,
                hashBlock.ToString());
        return true;
    }

    if (!CvnVerifySignature(hashBlock, block.creatorSignature, block.nCreatorId))
        return error("%s : invalid creator signature", __func__);

    if (!CvnVerifyChainSignature(block))
        return error("%s : invalid chain signature", __func__);

    // check if creator ID matches consensus rules
    uint32_t nBlockCreator = CheckNextBlockCreator(pindexPrev, block.nTime);

    if (!nBlockCreator)
        return error("%s : FATAL: can not determine block creator for %s", __func__, hashBlock.ToString());

    if (nBlockCreator != block.nCreatorId)
        return error("%s : block %s can not be created by 0x%08x but by 0x%08x", __func__, hashBlock.ToString(), block.nCreatorId, nBlockCreator);

    const uint32_t nChainSigs = GetNumChainSigs(&block);
    const uint32_t nPrevChainSigs = GetNumChainSigs(pindexPrev);

    if (!nChainSigs || !nPrevChainSigs) {
        LogPrintf("%s : could not determine number of signatures: %d|%d\n", __func__, nChainSigs, nPrevChainSigs);
        return false;
    }

    LogPrint("cvn", "%s : checking # sigs (prev: %u, this: %u) of block %s created by 0x%08x\n", __func__,
            nPrevChainSigs, nChainSigs, hashBlock.ToString(), block.nCreatorId);

    // only do advanced checks if we have a decrease in the number of signatures
    if (nPrevChainSigs > nChainSigs) {
        // this block requires at least dynParams.nPercentageOfSignatureMean of the number of nSignatureMean
        if (!HasEnoughSignatures(pindexPrev, nChainSigs)) {
            LogPrintf("%s : past signatures [", __func__);
            CBlockIndex *pindexDebug = pindexPrev;
            uint32_t i = 0, nSignatures = 0;
            while (i < dynParams.nBlocksToConsiderForSigCheck && pindexDebug != NULL) {
                uint32_t nDebugSigs = GetNumChainSigs(pindexDebug);
                nSignatures += nDebugSigs;
                LogPrintf("%s%02u", i ? ", " : " ", nDebugSigs);
                pindexDebug = pindexDebug->pprev;
                i++;
            }
            float nSignaturesMean = i ? (float) nSignatures / (float) i : 0.0f;
            LogPrintf(" ], nSignatureMean: %f, nBlock: %u\n", nSignaturesMean, i);
            return error("%s: not enough signatures available in block %s. Mean: %f, This: %u", __func__,
                    block.GetHash().ToString(), nSignaturesMean, nChainSigs);
        }
    }

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

bool CheckForSufficientNumberOfCvns(const CBlock& block, const Consensus::Params& params)
{
    assert(block.HasCvnInfo());

    const uint256 hashBlock = block.GetHash();

    BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
    if (mi == mapBlockIndex.end()) {
        if (hashBlock != params.hashGenesisBlock) {
            LogPrintf("%s : can not check orphan block %s created by 0x%08x, delaying check.\n", __func__,
                        hashBlock.ToString(), block.nCreatorId);
            return false;
        } else
            return true;
    }

    CBlockIndex * const pindexPrev = (*mi).second;

    if (!HasEnoughSignatures(pindexPrev, block.vCvns.size())) {
        return error("not enough CVNs available to continue blockchain: %d", block.vCvns.size());
    }

    return true;
}

bool CheckForDuplicateAdminSigs(const CBlock& block)
{
    if (block.vAdminIds.empty() || block.vAdminIds.size() == 1)
        return true;

    if (block.vAdminIds.size() > mapChainAdmins.size())
        return error("detected too many admin sigs: %d/%d", block.vAdminIds.size(), mapChainAdmins.size());

    boost::unordered_set<uint32_t> sNodeIds;

    BOOST_FOREACH(const uint32_t &id, block.vAdminIds)
        if (!sNodeIds.insert(id).second)
            return error("detected duplicate admin Id: 0x%08x", id);

    return true;
}

bool CheckForDuplicateMissingChainSigs(const CBlock& block)
{
    if (block.vMissingSignerIds.empty() || block.vMissingSignerIds.size() == 1)
        return true;

    if (block.vMissingSignerIds.size() > mapCVNs.size())
        return error("detected too many missing creators sigs: %d/%d", block.vMissingSignerIds.size(), mapCVNs.size());

    boost::unordered_set<uint32_t> sNodeIds;

    BOOST_FOREACH(const uint32_t &id, block.vMissingSignerIds)
        if (!sNodeIds.insert(id).second)
            return error("detected duplicate missing chains sig Id: 0x%08x", id);

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

    if (!nLastAddedNode || !pindexFound)
        return 0;

    // if the last added node has created a block there is no new CVN that needs to be bootstrapped
    for (const CBlockIndex* pindex = pindexStart; pindex && pindex != pindexFound; pindex = pindex->pprev) {
        if (pindex->nCreatorId == nLastAddedNode)
            return 0;
    }

    return nLastAddedNode;
}

/* try to find a node that did not create a block within the
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
    unsigned int nBlocksToScan = POC_BLOCKS_TO_SCAN;
    size_t nRegisteredCVNs = mapCVNs.size();
    for (const CBlockIndex* pindex = pindexStart; pindex && nBlocksToScan; pindex = pindex->pprev, nBlocksToScan--) {
        if ((pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) {
            LogPrintf("%s : block not on a connected chain. Unable to determine the correct creator ID: %s\n", __func__, pindex->ToString());
            return 0;
        }

        if (!mapCVNs.count(pindex->nCreatorId) || mapBannedCVNs.count(pindex->nCreatorId))
            continue; // ignore CVNs that were deactivated or banned

        // if the creator has not been considered yet add it to the list of candidates
        if (setCreatorCandidates.insert(pindex->nCreatorId).second)
            vCreatorCandidates.push_back(pindex->nCreatorId);

        // record the number of signatures within the nMinSuccessiveSignatures range
        if (nMinSignatures) {
            nMinSignatures--;
            vector<uint32_t> vMissing = pindex->vMissingSignerIds;
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
        LogPrint("cvnnext", "%s : CVN 0x%08x needs to be bootstrapped\n", __func__, nNextCreatorId);
        vCreatorCandidates.push_back(nNextCreatorId);
    } else if (vCreatorCandidates.size() < nRegisteredCVNs) {
        nNextCreatorId = FindDormantNode(pindexStart, mapLastSignatures, setCreatorCandidates, dynParams.nMinSuccessiveSignatures);

        if (nNextCreatorId) {
            LogPrintf("%s : dormant CVN 0x%08x detected - activating...\n", __func__, nNextCreatorId);
            vCreatorCandidates.push_back(nNextCreatorId);
        }
    }

    // the last entry in the list has the highest priority (aka. time-weight)
    CandidateIterator itCandidates = vCreatorCandidates.rbegin();

    if (!vCreatorCandidates.size()) {
        LogPrintf("%s : could not find any creator node candidates\n", __func__);
        return 0;
    }

    uint32_t nCandidateOffset = GetCandidateOffset(pindexStart->nTime, nTimeToTest);
    if (nCandidateOffset >= vCreatorCandidates.size()) {
        LogPrint("cvnnext", "%s : WARN, CandidateOffset exceeds limits: %u >= %u\n", __func__, nCandidateOffset, vCreatorCandidates.size());
        nCandidateOffset %= vCreatorCandidates.size();
        LogPrint("cvnnext", "%s : reducing offset to %u\n", __func__, nCandidateOffset);
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
            LogPrintf("%s : could not find a CVN that signed enough successive blocks. Lowering number of required sigs to %u\n", __func__, nMinSignatures);
        }
    } while (nMinSignatures);

    if (!nNextCreatorId)
        LogPrintf("%s : could not find any node ID that should create the next block #%u\n", __func__, pindexStart->nHeight + 1);

    LogPrint("cvnnext", "%s : NODE ID 0x%08x should create the next block #%u\n", __func__, nNextCreatorId, pindexStart->nHeight + 1);

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

bool AddNonceAdmin(const CAdminNonce& msg)
{
    if (!VerifyAdminSignature(msg.GetHash(), msg.msgSig, msg.nAdminId))
        return false;

    LOCK(cs_mapAdminNonces);

    if (mapAdminNonces.find(msg.nAdminId) != mapAdminNonces.end()) {
        LogPrintf("%s : received duplicate admin nonce from admin ID 0x%08x for tip %s\n", __func__, msg.nAdminId, msg.hashRootBlock.ToString());
        return false;
    }

    if (chainActive.Tip()->GetBlockHash() != msg.hashRootBlock) {
        LogPrintf("%s : received invalid admin nonce from admin ID 0x%08x for outdated tip %s\n", __func__, msg.nAdminId, msg.hashRootBlock.ToString());
        return false;
    }

    mapAdminNonces[msg.nAdminId] = msg.publicNonce;

    LogPrint("cvnsig", "%s : add admin nonce from admin ID 0x%08x, hash %s\n", __func__, msg.nAdminId,
            msg.hashRootBlock.ToString());

    return true;
}

void RelayNonceAdmin(const CAdminNonce& msg)
{
    CInv inv(MSG_CHAIN_ADMIN_NONCE, msg.GetHash());
    {
        LOCK(cs_mapRelayAdminNonces);
        mapRelayAdminNonces.insert(std::make_pair(inv.hash, msg));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayPoCMessages)
            continue;
        pnode->PushInventory(inv);
    }
}

void RelayAdminSignature(const CAdminPartialSignature& msg)
{
    CInv inv(MSG_CHAIN_ADMIN_SIGNATURE, msg.GetHash());
    {
        LOCK(cs_mapRelayAdminSigs);
        mapRelayAdminSigs.insert(std::make_pair(inv.hash, msg));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayPoCMessages)
            continue;
        pnode->PushInventory(inv);
    }
}

int32_t GetPoolAge(const CNoncePool &pool, CBlockIndex *pTip)
{
    uint32_t nPoolAge = 0;
    CBlockIndex *pindexTip = pTip;

    while (pindexTip && nPoolAge < pool.vPublicNonces.size()) {
        if (pool.hashRootBlock == pindexTip->GetBlockHash())
            return nPoolAge;

        pindexTip = pindexTip->pprev;
        nPoolAge++;
    }

    return -1;
}

bool AddNoncePool(CNoncePool& msg)
{
    if (!CvnVerifySignature(msg.GetHash(), msg.msgSig, msg.nCvnId))
        return false;

    LOCK(cs_mapNoncePool);
    size_t nSize = msg.vPublicNonces.size();

    // check if we've received an old pool
    if (mapNoncePool.count(msg.nCvnId)) {
        if (msg.nCreationTime < mapNoncePool[msg.nCvnId].nCreationTime) {
            LogPrintf("AddNoncePool : received pool with old time stamp, ignoring it. CvnID 0x%08x, hash %s, size: %d\n", msg.nCvnId, msg.hashRootBlock.ToString(), nSize);
            return true;
        }

        // already have this
        if (msg.nCreationTime == mapNoncePool[msg.nCvnId].nCreationTime)
            return true;
    }

    if (nSize < 1 || nSize > MAX_NONCE_POOL_SIZE) {
        LogPrintf("AddNoncePool : pool size out of bounds. CvnID 0x%08x, hash %s, size: %d\n", msg.nCvnId, msg.hashRootBlock.ToString(), nSize);
        return false;
    }

    CBlockIndex *pTip = chainActive.Tip();
    int32_t nPoolAge = GetPoolAge(msg, pTip);

    if (nPoolAge < 0) {
        LogPrintf("AddNoncePool : could not determine pool age, root block not (yet) available. Saving it for later. CvnID 0x%08x, hash %s, size: %d\n", msg.nCvnId, msg.hashRootBlock.ToString(), nSize);
        msg.fRecheck = true;
        mapNoncePoolCheckLater[msg.nCvnId] = msg;
        return true;
    }

    msg.nHeightAdded = pTip->nHeight - nPoolAge;

    if (nPoolAge >= (int32_t)nSize) {
        LogPrintf("AddNoncePool : nonce pool too old. CvnID 0x%08x, hash %s, size: %d, age: %d\n", msg.nCvnId, msg.hashRootBlock.ToString(), nSize, nPoolAge);
        return false;
    }

    LogPrint("cvnsig", "AddNoncePool : %s nonce pool for 0x%08x, age %d, size %d, creationTime %u, root hash %s\n",
            (mapNoncePool.count(msg.nCvnId) ? "replacing" : "adding"),
            msg.nCvnId, nPoolAge, msg.vPublicNonces.size(), msg.nCreationTime, msg.hashRootBlock.ToString());

    mapNoncePool[msg.nCvnId] = msg;

    return true;
}

void RelayNoncePool(const CNoncePool& msg)
{
    CInv inv(MSG_CVN_PUB_NONCE_POOL, msg.GetHash());

    {
        LOCK(cs_mapRelayNonces);
        mapRelayNonces.insert(std::make_pair(inv.hash, msg));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayPoCMessages)
            continue;

        pnode->PushInventory(inv);
    }
}

bool AddAdminSignature(const CAdminPartialSignature& msg)
{
    if (!VerifyAdminSignature(msg.GetHash(), msg.msgSig, msg.nAdminId))
        return false;

    LOCK(cs_mapAdminSigs);
    if (mapAdminSigs.find(msg.nAdminId) != mapAdminSigs.end()) {
        LogPrintf("%s : received duplicate admin signature from admin ID 0x%08x for tip %s\n", __func__, msg.nAdminId, msg.hashRootBlock.ToString());
        return false;
    }

    if (chainActive.Tip()->GetBlockHash() != msg.hashRootBlock) {
        LogPrintf("%s : received invalid admin signature from admin ID 0x%08x for outdated tip %s\n", __func__, msg.nAdminId, msg.hashRootBlock.ToString());
        return false;
    }

    mapAdminSigs[msg.nAdminId] = msg;

    LogPrint("cvnsig", "%s : add admin sig 0x%08x, hash %s, admin IDs: %s\n", __func__, msg.nAdminId,
            msg.hashRootBlock.ToString(), CreateSignerIdList(msg.vSignerIds));

    return true;
}

void ExpireChainAdminData()
{
    LOCK2(cs_mapAdminNonces, cs_mapAdminSigs);

    mapAdminNonces.clear();
    mapAdminSigs.clear();
}

void CheckNoncePools(CBlockIndex *pindex)
{
    LOCK(cs_mapNoncePool);

    CNoncePoolType::iterator it = mapNoncePool.begin();
    while (it != mapNoncePool.end()) {
        const CNoncePool &p = it->second;
        const uint32_t nPoolAge = GetPoolAge(p, pindex);
        const CNoncePoolType::iterator itErase = it++;
        const bool fCvnRemoved = mapCVNs.find(p.nCvnId) == mapCVNs.end();

        if (fCvnRemoved || nPoolAge >= p.vPublicNonces.size()) {
            LogPrintf("%s, removing pool for 0x%08x.\n", (fCvnRemoved ? "CVN has been removed from the network" : "nonce pool expired"), itErase->first);
            mapNoncePool.erase(itErase);
        }
    }

    it = mapNoncePoolCheckLater.begin();
    while (it != mapNoncePoolCheckLater.end()) {
        CNoncePool &p = it->second;
        const CNoncePoolType::iterator itErase = it++;
        if (p.hashRootBlock == pindex->GetBlockHash()) {
            if (mapCVNs.find(p.nCvnId) != mapCVNs.end()) {
                LogPrintf("reconsidering nonce pool for 0x%08x\n", itErase->first);
                AddNoncePool(p);
            }
            mapNoncePoolCheckLater.erase(itErase);
        }
    }
}

#ifdef USE_CVN
static bool GetFeeScript(CReserveScript &script)
{
#ifdef ENABLE_WALLET
    GetMainSignals().FeeScript(script);
#else
    if (!mapArgs.count("-cvnfeeaddress")) {
        LogPrintf("%s : option -cvnfeeaddress must be given if wallet support is not compiled in.\n", __func__);
        return false;
    }
#endif
    if (mapArgs.count("-cvnfeeaddress")) {
        CBitcoinAddress feeAddress(GetArg("-cvnfeeaddress", ""));
        if (feeAddress.IsValid()) {
            script.reserveScript = GetScriptForDestination(feeAddress.Get());
            LogPrintf("CVN fee address: %s\n", feeAddress.ToString());
        } else {
#ifdef ENABLE_WALLET
            LogPrintf("%s : the fee address %s is invalid. Falling back to standard wallet address.\n", __func__, feeAddress.ToString());
#else
            LogPrintf("%s : the fee address %s is invalid. Can not start CVN.\n", __func__, feeAddress.ToString());
            return false;
#endif
        }
    }

    return true;
}

//
// CNoncesPoolDB
//
CNoncesPoolDB::CNoncesPoolDB()
{
    pathNonces = GetDataDir() / "pool.dat";
}

bool CNoncesPoolDB::Write(const CNoncePool& pool, const vector<CSchnorrPrivNonce>& vPrivateNonces, const vector<uint8_t>& vNonceHandles)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string tmpfn = strprintf("pool.dat.%04x", randv);

    // serialize nonces, checksum data up to that point, then append the checksum
    CDataStream ssNonces(SER_DISK, CLIENT_VERSION);
    ssNonces << FLATDATA(Params().MessageStart());
    ssNonces << pool;
    ssNonces << vPrivateNonces;
    ssNonces << vNonceHandles;

    uint256 hash = Hash(ssNonces.begin(), ssNonces.end());
    ssNonces << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = GetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: Failed to open file %s", __func__, pathTmp.string());

    // Write and commit header, data
    try {
        fileout << ssNonces;
    }
    catch (const std::exception& e) {
        return error("%s: Serialize or I/O error - %s", __func__, e.what());
    }
    FileCommit(fileout.Get());
    fileout.fclose();

    // replace existing nonces.dat, if any, with new nonces.dat.XXXX
    if (!RenameOver(pathTmp, pathNonces))
        return error("%s: Rename-into-place failed", __func__);

    return true;
}

bool CNoncesPoolDB::Read(CNoncePool& pool, vector<CSchnorrPrivNonce>& vPrivateNonces, vector<uint8_t>& vNonceHandles)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathNonces.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: Failed to open file %s", __func__, pathNonces.string());

    // use file size to size memory buffer
    uint64_t fileSize = boost::filesystem::file_size(pathNonces);
    uint64_t dataSize = 0;
    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
        dataSize = fileSize - sizeof(uint256);
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();

    CDataStream ssNonces(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssNonces.begin(), ssNonces.end());
    if (hashIn != hashTmp)
        return error("%s: Checksum mismatch, data corrupted", __func__);

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (network specific magic number) and ..
        ssNonces >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
            return error("%s: Invalid network magic number", __func__);

        // de-serialize address data into the vector
        ssNonces >> pool;
        ssNonces >> vPrivateNonces;
        ssNonces >> vNonceHandles;

        if (pool.nCvnId != nCvnNodeId)
            return error("%s: CVN ID mismatch", __func__);
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    return true;
}

void SaveNoncesPool()
{
    if (!nCvnNodeId || !mapNoncePool.count(nCvnNodeId) || !fNoncePoolInitialsed)
        return;

    CNoncesPoolDB pooldb;
    vector<uint8_t> vNonceHandles;
#ifdef USE_FASITO
    vNonceHandles = fasito.vNonceHandles;
#endif
    pooldb.Write(mapNoncePool[nCvnNodeId], vNoncePrivate, vNonceHandles);

    LogPrint("cvnsig", "Flushed pool with %d public nonces and %d private nonces and %d nonces handles to pool.dat\n",
            mapNoncePool[nCvnNodeId].vPublicNonces.size(), vNoncePrivate.size(), vNonceHandles.size());
}

bool static CreateNonceWithKey(const uint256& hashData, const CKey& privKey, unsigned char *pPrivateData, CSchnorrNonce& noncePublic)
{
    uint256 hashRandom;
    GetStrongRandBytes(&hashRandom.begin()[0], 32);

    if (!privKey.SchnorrCreateNoncePair(hashData, noncePublic, pPrivateData, hashRandom)) {
        LogPrintf("%s : could not create block signature\n", __func__);
        return false;
    }

#if POC_DEBUG
    LogPrintf("%s : OK\n  Hash: %s\n  pubk: %s\n  pubn: %s\n privn: %s\n", __func__,
            hashData.ToString(),
            cvnPubKey.ToString(),
            noncePublic.ToString(),
            HexStr(pPrivateData));
#endif
    return true;
}

bool CreateNoncePairForHash(CSchnorrNonce& noncePublic, unsigned char *pPrivateData, const uint256& hashData, const uint32_t& nNodeId, const bool fUseFasito, const bool fAdmin)
{
    if (fAdmin) {
        if (!nNodeId) {
            LogPrintf("%s : chain admin not logged on\n", __func__);
            return false;
        }

        if (!mapChainAdmins.count(nNodeId)) {
            LogPrintf("%s : could not find ChainAdmin for signer ID 0x%08x\n", __func__, nNodeId);
            return false;
        }
    } else {
        if (!nNodeId) {
            LogPrintf("%s : CVN node not initialized\n", __func__);
            return false;
        }

        if (!mapCVNs.count(nNodeId)) {
            LogPrintf("%s : could not find CvnInfo for signer ID 0x%08x\n", __func__, nNodeId);
            return false;
        }

        if (!mapArgs.count("-cvn")) {
            LogPrintf("%s : this node was not configured to run as CVN\n", __func__, nNodeId);
            return false;
        }
    }

    const CSchnorrPubKey& pubKey = fAdmin ? mapChainAdmins[nNodeId].pubKey : mapCVNs[nNodeId].pubKey;

    if (fUseFasito) {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrint("cvn", "%s : Fasito is not ready.\n", __func__);
            return false;
        }
        if (!CreateNonceWithFasito(hashData, fAdmin ? fasito.nADMINKeyIndex : fasito.nCVNKeyIndex, pPrivateData, noncePublic, pubKey)) {
            noncePublic.SetNull();
            return false;
        }
#else
        LogPrintf("%s : this wallet was not compiled with Fasito support.\n", __func__);
        return false;
#endif
    } else {
        if ((fAdmin && pubKey != adminPubKey) || (!fAdmin && pubKey != cvnPubKey)) {
            LogPrintf("%s : key does not match node ID\n"
                    "  block chain pubkey: %s\n"
                    "  FILE pubkey: %s\n", __func__, pubKey.ToString(), cvnPubKey.ToString());
            return false;
        }

        if (!CreateNonceWithKey(hashData, fAdmin ? adminPrivKey : cvnPrivKey, pPrivateData, noncePublic)) {
            noncePublic.SetNull();
            return false;
        }
    }

    return true;
}

bool static CvnSignWithKey(const uint256& hashToSign, const CKey& privKey, const CSchnorrPubKey &pubKey, CSchnorrSig& signature)
{
    if (!privKey.IsValid()) {
        LogPrintf("%s : could not create signature. Private key is invalid.\n", __func__);
        return false;
    }

    if (!privKey.SchnorrSign(hashToSign, signature)) {
        LogPrintf("%s : could not create signature\n", __func__);
        return false;
    }

    if (!CvnVerifySignature(hashToSign, signature, pubKey)) {
        LogPrintf("%s : created invalid signature\n", __func__);
        return false;
    }

#if POC_DEBUG
    LogPrintf("%s : OK\n  Hash: %s\n  pubk: %s\n   sig: %s\n", __func__,
            hashToSign.ToString(),
            cvnPubKey.ToString(),
            signature.ToString());
#endif
    return true;
}

bool static CvnSignPartialWithKey(const uint256& hashToSign, const CKey& cvnPrivKey, const CSchnorrPubKey& sumPublicNoncesOthers, CSchnorrSig& signature, const int nPoolOffset)
{
    if (nPoolOffset >= (int)vNoncePrivate.size()) {
        LogPrintf("%s : could not create chain signature nonce pool offset out of range: %d\n", __func__, nPoolOffset);
        return false;
    }

    if (vNoncePrivate[nPoolOffset].IsNull()) {
        LogPrintf("%s : could not create chain signature no private nonce available\n", __func__);
        return false;
    }

    if (!cvnPrivKey.SchnorrSignParial(hashToSign, sumPublicNoncesOthers, vNoncePrivate[nPoolOffset], signature)) {
        LogPrintf("%s : could not create chain signature\n", __func__);
        return false;
    }

#if POC_DEBUG
    LogPrintf("%s : OK\n  Hash: %s\nsigner: 0x%08x\n   sum: %s\n   sig: %s\noffset: %d\n nPriv: %d\n", __func__,
            hashToSign.ToString(), signature.ToString(),
            sumPublicNoncesOthers.ToString(), signature.ToString(), nPoolOffset, vNoncePrivate[nPoolOffset].ToString());
#endif
    return true;
}

bool CvnSignHash(const uint256 &hashToSign, CSchnorrSig& signature)
{
    if (GetArg("-cvn", "") == "fasito") {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrintf("%s : Fasito is not ready.\n", __func__);
            return false;
        }
        return CvnSignWithFasito(hashToSign, fasito.nCVNKeyIndex, signature);
#else
        LogPrintf("%s : this wallet was not compiled with Fasito support.\n", __func__);
        return false;
#endif
    } else {
        return CvnSignWithKey(hashToSign, cvnPrivKey, cvnPubKey, signature);
    }

}

bool AdminSignHash(const uint256 &hashToSign, CSchnorrSig& signature, bool fFasito)
{
    if (fFasito) {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrintf("%s : Fasito is not ready.\n", __func__);
            return false;
        }
        return CvnSignWithFasito(hashToSign, fasito.nADMINKeyIndex, signature);
#else
        LogPrintf("%s : this wallet was not compiled with Fasito support.\n", __func__);
        return false;
#endif
    } else {
        return CvnSignWithKey(hashToSign, adminPrivKey, adminPubKey, signature);
    }
}

static bool AdminSignPartialWithKey(const uint256& hashToSign, const CKey& adminPrivKey, const CSchnorrPubKey& sumPublicNoncesOthers, CSchnorrSig& signature, const CSchnorrPrivNonce& privNonce)
{
    if (privNonce.IsNull()) {
        LogPrintf("%s : could not create chain signature no private nonce available\n", __func__);
        return false;
    }

    if (!adminPrivKey.SchnorrSignParial(hashToSign, sumPublicNoncesOthers, privNonce, signature)) {
        LogPrintf("%s : could not create chain signature\n", __func__);
        return false;
    }

#if POC_DEBUG
    LogPrintf("%s : OK\n  Hash: %s\nsigner: 0x%08x\n   sum: %s\n   sig: %s\n", __func__,
            hashToSign.ToString(), nChainAdminId,
            sumPublicNoncesOthers.ToString(), signature.ToString());
#endif
    return true;
}

bool AdminSignPartial(const uint256 &hashToSign, CAdminPartialSignatureUnsinged &signature, const uint32_t &nAdminId, const CSchnorrPrivNonce *privNonce, const uint8_t nHandle)
{
    if (!nAdminId) {
        LogPrintf("%s : admin id not available\n", __func__);
        return false;
    }

    if (!mapChainAdmins.count(nAdminId)) {
        LogPrintf("%s : could not find chain admin id for signer ID 0x%08x\n", __func__, nAdminId);
        return false;
    }

    const bool fFasito = (privNonce == NULL);

    signature.nAdminId      = nAdminId;
    signature.hashRootBlock = chainActive.Tip()->GetBlockHash();
    signature.hashChainData = hashToSign;
    signature.nCreationTime = GetTime();

    /* create a plain EC-Schnorr signature in case only one admin ID is used */
    if (mapAdminNonces.size() == 1) {
        signature.vSignerIds.push_back(nAdminId);
        return AdminSignHash(hashToSign, signature.signature, fFasito);
    }

    CSchnorrPubKey sumPublicNoncesOthers;
    vector<uint32_t> vAdminIds;
    if (!CreateSumPublicAdminNoncesOthers(sumPublicNoncesOthers, nAdminId, vAdminIds))
        return false;

    if (fFasito) {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrint("cvn", "%s : not logged into Fasito. Cannot create partial signature.\n", __func__);
            return false;
        }

        if (!AdminSignPartialWithFasito(hashToSign, fasito.nADMINKeyIndex, sumPublicNoncesOthers, signature.signature, nHandle))
            return false;
#else
        LogPrintf("%s : this wallet was not compiled with Fasito support.\n", __func__);
        return false;
#endif
    } else {
        if (!AdminSignPartialWithKey(hashToSign, adminPrivKey, sumPublicNoncesOthers, signature.signature, *privNonce))
            return false;
    }

    signature.vSignerIds = vAdminIds;

    return VerifyPartialSignature(hashToSign, signature.signature, mapChainAdmins[nAdminId].pubKey, sumPublicNoncesOthers);
}

bool CvnSignPartial(const uint256 &hashPrevBlock, CCvnPartialSignatureUnsinged &signature, const uint32_t &nNextCreator, const uint32_t &nNodeId, const vector<uint32_t> &vMissingSignerIds, const int nPoolOffset)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashPrevBlock << nNextCreator;

    if (!nNodeId) {
        LogPrintf("%s : CVN node not initialised\n", __func__);
        return false;
    }

    if (!mapCVNs.count(nNodeId)) {
        LogPrintf("%s : could not find CvnInfo for signer ID 0x%08x\n", __func__, nNodeId);
        return false;
    }

    if (!mapArgs.count("-cvn")) {
        LogPrintf("%s : this node was not configured to run as CVN\n", __func__);
        return false;
    }

    signature.nSignerId     = nNodeId;
    signature.nCreatorId    = nNextCreator;
    signature.hashPrevBlock = hashPrevBlock;
    signature.nCreationTime = GetTime();

    /* create a plain Schnorr signature in case only one CVN is available (e.g. during bootstrap) */
    if (mapCVNs.size() == 1)
        return CvnSignHash(hasher.GetHash(), signature.signature);

    CSchnorrPubKey sumPublicNoncesOthers;
    if (!CreateSumPublicNoncesOthers(sumPublicNoncesOthers, nNextCreator, nNodeId, vMissingSignerIds))
        return false;

    UpdateHashWithMissingIDs(hasher, vMissingSignerIds);

    uint256 hashToSign = hasher.GetHash();

    if (GetArg("-cvn", "") == "fasito") {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrint("cvn", "%s : not logged into Fasito. Cannot create partial signature.\n", __func__);
            return false;
        }

        if (!CvnSignPartialWithFasito(hashToSign, fasito.nCVNKeyIndex, sumPublicNoncesOthers, signature.signature, nPoolOffset))
            return false;
#else
        LogPrintf("%s : this wallet was not compiled with Fasito support.\n", __func__);
        return false;
#endif
    } else {
        if (!CvnSignPartialWithKey(hashToSign, cvnPrivKey, sumPublicNoncesOthers, signature.signature, nPoolOffset))
            return false;
    }

    signature.vMissingSignerIds = vMissingSignerIds;

    return VerifyPartialSignature(hashToSign, signature.signature, mapCVNs[nNodeId].pubKey, sumPublicNoncesOthers);
}

int CombinePartialSignatures(CSchnorrSig& allsig, uint8_t *sigs[], int nSignatures)
{
    if (nSignatures < 2)
        return false;

    LogPrint("cvnsig", "%s : combining %u signautres\n",__func__ , nSignatures);
    return secp256k1_schnorr_partial_combine(secp256k1_context_none, allsig.begin(), sigs, nSignatures);
}

bool CvnSignBlock(CBlock& block)
{
    CCvnInfo cvnInfo = mapCVNs[block.nCreatorId];

    if (GetArg("-cvn", "") == "file" && cvnInfo.pubKey != cvnPubKey) {
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

static bool SendCVNSignature(POCStateHolder &s, const vector<uint32_t> &vMissingSignatures)
{
    const CBlockIndex *pTip = s.pindexPrev;
    uint32_t nNextCreator = CheckNextBlockCreator(pTip, GetAdjustedTime());

    if (!nNextCreator) {
        LogPrintf("%s : could not find next block creator\n", __func__);
        return false;
    }

    uint256 hashPrevBlock = pTip->GetBlockHash();

    int nPoolOffset = chainActive.Tip()->nHeight - mapNoncePool[nCvnNodeId].nHeightAdded;
    CCvnPartialSignatureUnsinged signature;

    if (!CvnSignPartial(hashPrevBlock, signature, nNextCreator, nCvnNodeId, vMissingSignatures, nPoolOffset)) {
        LogPrintf("%s : could not create sig for 0x%08x by 0x%08x, hash %s\n", __func__,
                nNextCreator, nCvnNodeId, hashPrevBlock.ToString());
        return false;
    }

    CCvnPartialSignature msg(signature);

    CSchnorrSig msgSig;
    if (!CvnSignHash(msg.GetHash(), msgSig)) {
        LogPrintf("%s : could not sign signature message\n", __func__);
        return false;
    }

    msg.msgSig = msgSig;

    {
        LOCK(cs_main);
        if (AddCvnSignature(msg))
            RelayCvnSignature(msg);
    }

    s.commonRxs.push_back(msg.signature.GetRx());
    return true;
}

static bool SetUpNoncePool()
{
#ifdef USE_FASITO
    bool fUseFasito = GetArg("-cvn", "fasito") == "fasito";
    vector<uint8_t>& vNonceHandles = fasito.vNonceHandles;
#else
    vector<uint8_t> vNonceHandles;
    bool fUseFasito = false;
#endif
    CNoncesPoolDB pooldb;
    CNoncePool pool;
    if (!pooldb.Read(pool, vNoncePrivate, vNonceHandles)) {
        return false;
    }

    if (pool.vPublicNonces.empty()) {
        LogPrintf("%s : nonce pool is empty\n", __func__);
        return false;
    }

    if (fUseFasito && vNonceHandles.size() != pool.vPublicNonces.size()) {
        LogPrintf("%s : number of private handle/public nonces mismatch: %d/%d\n", __func__, vNonceHandles.size(), pool.vPublicNonces.size());
        return false;
    }

    if (!fUseFasito && vNoncePrivate.size() != pool.vPublicNonces.size()) {
        LogPrintf("%s : number of private/public nonces mismatch: %d/%d\n", __func__, vNoncePrivate.size(), pool.vPublicNonces.size());
        return false;
    }

    int nPoolSize = pool.vPublicNonces.size();
    LogPrintf("Verifying nonce pool with %d entires...", nPoolSize);
    for (int i = 0 ; i < nPoolSize ; i++) {
        if (!VerifyNoncePoolEntry(i)) {
            LogPrintf("%s : nonce pool is invalid. Re-creating it.\n", __func__);
            return false;
        }
    }

    LogPrintf("OK\n");

    {
        LOCK(cs_mapNoncePool);
        mapNoncePool.erase(pool.nCvnId);
    }
    return AddNoncePool(pool);
}

static bool CreateNoncePoolFile(CNoncePool& pool, const uint16_t nPoolSize, CNoncePool * const oldPool)
{
    uint256 hashData;
    GetStrongRandBytes(&hashData.begin()[0], 32);

    LOCK(cs_mapNoncePool);

    int32_t nOldPoolAge = 0;
    if (oldPool) {
        nOldPoolAge = GetPoolAge(*oldPool, chainActive.Tip());
        if (nOldPoolAge > 0 && vNoncePrivate.size() == oldPool->vPublicNonces.size()) {
            vNoncePrivate.erase(vNoncePrivate.begin(), vNoncePrivate.begin() + nOldPoolAge);

            vector<CSchnorrNonce> &nonces = oldPool->vPublicNonces;
            nonces.erase(nonces.begin(), nonces.begin() + nOldPoolAge);
            pool.vPublicNonces = nonces;
        } else {
            vNoncePrivate.clear();
            nOldPoolAge = 0;
        }
    } else {
        vNoncePrivate.clear();
    }

    const uint16_t nCreateNew = nPoolSize - pool.vPublicNonces.size();

    for (uint16_t i = 0 ; i < nCreateNew ; i++) {
        CSchnorrNonce nonce;
        unsigned char privateData[32];
        if (!CreateNoncePairForHash(nonce, privateData, hashData, pool.nCvnId, false, false)) {
            pool.vPublicNonces.clear();
            return false;
        }

        CSchnorrPrivNonce pn(privateData);
        vNoncePrivate.push_back(pn);
        pool.vPublicNonces.push_back(nonce);
    }

    return true;
}

#ifdef USE_FASITO
static bool CreateNoncePoolFasito(CNoncePool& pool, const uint16_t nPoolSize, CNoncePool * const oldPool)
{
    uint256 hash4noncePool;
    GetStrongRandBytes(&hash4noncePool.begin()[0], 32);

    bool fClearPool = false;

    LOCK(cs_mapNoncePool);

    int32_t nOldPoolAge = 0;
    if (oldPool) {
        nOldPoolAge = GetPoolAge(*oldPool, chainActive.Tip());
        if (nOldPoolAge > 0 && fasito.vNonceHandles.size() == oldPool->vPublicNonces.size()) {
            fasito.vNonceHandles.erase(fasito.vNonceHandles.begin(), fasito.vNonceHandles.begin() + nOldPoolAge);

            vector<CSchnorrNonce> &nonces = oldPool->vPublicNonces;
            nonces.erase(nonces.begin(), nonces.begin() + nOldPoolAge);
            pool.vPublicNonces = nonces;
        } else {
            fClearPool = true;
            nOldPoolAge = 0;
        }
    } else {
        fClearPool = true;
    }

    if (fClearPool) {
        fasito.vNonceHandles.clear();
        if (!fasito.sendCommand("CLRPOOL")) {
            LogPrintf("could not clear nonce pool on Fasito\n");
            return false;
        }
    }

    const uint16_t nCreateNew = nPoolSize - pool.vPublicNonces.size();

    for (uint16_t i = 0 ; i < nCreateNew ; i++) {
        CSchnorrNonce nonce;
        unsigned char privateData[32];
        if (!CreateNoncePairForHash(nonce, privateData, hash4noncePool, pool.nCvnId, true, false)) {
            pool.vPublicNonces.clear();
            return false;
        }

        uint8_t *nHandle = (uint8_t *) privateData;

        fasito.vNonceHandles.push_back(*nHandle);
        pool.vPublicNonces.push_back(nonce);
        LogPrint("cvnsig", "CreateNoncePoolFasito : add to pool key #%d (handle: %d): %s\n", i, *nHandle, nonce.ToString());
    }

    return false;
}
#endif

void CreateNewNoncePool(const POCStateHolder& s)
{
    uint16_t nPoolSize = GetArg("-poolsizenonces", DEFAULT_NONCE_POOL_SIZE);
    if (nPoolSize > MAX_NONCE_POOL_SIZE)
        nPoolSize = MAX_NONCE_POOL_SIZE;

    if (nPoolSize < 1)
        nPoolSize = DEFAULT_NONCE_POOL_SIZE;

    CNoncePool pool;
    pool.nCvnId        = s.nNodeId;
    pool.hashRootBlock = s.GetPrevBlockHash();
    pool.nCreationTime = GetAdjustedTime();

    CNoncePool *oldPool = NULL;
    if (mapNoncePool.count(s.nNodeId)) {
        oldPool = &mapNoncePool[s.nNodeId];
    }

    if (GetArg("-cvn", "") == "file") {
        CreateNoncePoolFile(pool, nPoolSize, oldPool);
    }
#ifdef USE_FASITO
    else {
        CreateNoncePoolFasito(pool, nPoolSize, oldPool);
    }
#else
    else {
        LogPrintf("cannot create pool. Fasito support not compiled in.\n");
        return;
    }
#endif

    if (!CvnSignHash(pool.GetHash(), pool.msgSig)) {
        pool.vPublicNonces.clear();
        return;
    }

    LOCK(cs_main);
    if (AddNoncePool(pool)) {
        SaveNoncesPool();
        RelayNoncePool(pool);
    }
}

static void FindSignerIDsWithMissingNonces(vector<uint32_t> &vSignerIdsWithMissingNonces)
{
    LOCK(cs_mapNoncePool);

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs) {
        if (mapNoncePool.find(cvn.first) == mapNoncePool.end()) {
            vSignerIdsWithMissingNonces.push_back(cvn.first);
        }
    }
}

static bool NoncePoolsAvailable(const vector<uint32_t> &vMissingSignerIds)
{
    LOCK(cs_mapNoncePool);

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs) {
        // ignore those that are expected to be missing
        if (find(vMissingSignerIds.begin(), vMissingSignerIds.end(), cvn.first) != vMissingSignerIds.end())
            continue;

        if (mapNoncePool.find(cvn.first) == mapNoncePool.end()) {
            return false;
        }
    }

    return true;
}

static void handleCreateSignature(POCStateHolder& s)
{
    const bool fIsOverdue = (s.state == CREATE_SIGNATURE_OVERDUE);

    if (fIsOverdue)
        MilliSleep(3000); //give some time for other nodes

    if (s.commonRxs.empty()) {
        vector<uint32_t> vMissingSignerIds;
        FindSignerIDsWithMissingNonces(vMissingSignerIds);

        if (SendCVNSignature(s, vMissingSignerIds)) {
            s.state = fIsOverdue ? WAITING_FOR_SIGNATURES_OVERDUE : WAITING_FOR_SIGNATURES;
        } else {
            s.nSleep = 5; // something went wrong, wait 5 sec. and try again
        }
    }
}

static void handleCompleteSignatureSets(POCStateHolder& s)
{
    vector<vector<uint32_t> > vMissingSigsCandidates;
    if (sigHolder.HasSigSetsToContributeTo(vMissingSigsCandidates, s.nNodeId, mapCVNs.size())) {
        BOOST_FOREACH(const vector<uint32_t> &entry, vMissingSigsCandidates) {
            // we only try to co-sign if we have all required nonce pools available
            if (!NoncePoolsAvailable(entry))
                continue;

            if (!SendCVNSignature(s, entry)) {
                continue;
            }
        }
    }

    s.state  = WAITING_FOR_SIGNATURES;
}

static void handleWaitingForSignatures(POCStateHolder& s)
{
    if (sigHolder.HasCompleteSigSets(mapCVNs.size())) {
        s.state = WAITING_FOR_BLOCK;
        return;
    }

    const bool fIsOverdue = (s.state == WAITING_FOR_SIGNATURES_OVERDUE);
    int32_t nBaseTime = 0;

    if (fIsOverdue) {
        nBaseTime = GetAdjustedTime() - s.pindexPrev->nTime - dynParams.nBlockSpacing;

        if (nBaseTime  < 0)
            return;

        nBaseTime %= dynParams.nBlockSpacingGracePeriod;
    } else {
        nBaseTime = GetAdjustedTime() - s.pindexPrev->nTime;

        if (nBaseTime - (int32_t) dynParams.nBlockPropagationWaitTime < 0)
            return;

        nBaseTime -= dynParams.nBlockPropagationWaitTime;
    }

    if (!(nBaseTime % dynParams.nRetryNewSigSetInterval)) {
        /* We have not received all the expected partial signatures for any set.
         * Periodically (nRetryNewSigSetInterval) find the missing node IDs and try without them. */

        vector<uint32_t> vMissingSignerIds; // missing signer IDs from all commonRs we signed so far
        if (sigHolder.GetAllMissing(vMissingSignerIds, s.nNodeId, s.commonRxs, mapNoncePool, mapCVNs.size())) {
            FindSignerIDsWithMissingNonces(vMissingSignerIds);
            if (HasEnoughSignatures(s.pindexPrev, mapCVNs.size() - vMissingSignerIds.size())) {
                LogPrintf("Did not receive all signatures for set. Trying with smaller set of members. Missing: %s\n", CreateSignerIdList(vMissingSignerIds));

                if (!SendCVNSignature(s, vMissingSignerIds)) {
                    LogPrintf("%s : failed to create signature for set: %s\n", __func__, CreateSignerIdList(vMissingSignerIds));
                }
            } else {
                LogPrintf("No set with enough signatures available\n");
            }
        } else {
            LogPrintf("Nothing to. This node has already contributed to all sets.\n");
        }

        s.state  = COMPLETE_SIGNATURE_SETS;
        s.nSleep = dynParams.nRetryNewSigSetInterval - 5;
    }
}

static void handleWaitingForBlock(POCStateHolder& s)
{
    if (s.nNextCreator == s.nNodeId) {
        int32_t nBlockTime = GetAdjustedTime() - s.pindexPrev->nTime;
        if (nBlockTime >= (int32_t)dynParams.nBlockSpacing) {
            LOCK(cs_main);
            if (CreateBlock(s)) {
                s.state = WAITING_FOR_NEW_TIP;
            } else {
                s.nSleep = 3;
            }
        }
    }
}

static void handleWaitingForNewTip(POCStateHolder& s)
{
    return;
}

static void handleWaitingForBlockPropagation(POCStateHolder& s)
{
    if (!mapCVNs.count(s.nNodeId)) {
        LogPrintf("Your node (0x%08x) has been removed from the network.\n", s.nNodeId);
        s.state = WAITING_FOR_CVN_DATA;
        return;
    }

    int64_t nLastBlockSeconds = GetAdjustedTime() - s.pindexPrev->nTime;

    if (nLastBlockSeconds <= dynParams.nBlockPropagationWaitTime) {
        s.nSleep = dynParams.nBlockPropagationWaitTime - nLastBlockSeconds;
    }

    if (mapNoncePool.count(s.nNodeId)) {
        const CNoncePool &p = mapNoncePool[s.nNodeId];
        const uint32_t nPoolAge = GetPoolAge(p, s.pindexPrev);
        uint16_t nNoncesToKeep = GetArg("-poolkeepnonces", DEFAULT_NONCES_TO_KEEP);

        if (nPoolAge + nNoncesToKeep >= p.vPublicNonces.size()) {
            LogPrint("cvnsig", "local nonce pool expired, creating new pool, recycling %d nonces\n", nNoncesToKeep);
            CreateNewNoncePool(s);
        }
    } else {
        /* if it got cleared by a previous call to CheckNoncePools() */
        CreateNewNoncePool(s);
    }

    CheckNoncePools(s.pindexPrev);

    s.state = CREATE_SIGNATURE;
}

static void handleWaitingForCvnData(POCStateHolder& s)
{
    if (mapCVNs.count(s.nNodeId)) {
        LogPrintf("found CVN data for our node: %s\n", mapCVNs[s.nNodeId].ToString());
        s.state = WAITING_FOR_BLOCK_PROPAGATION;
        s.nSleep = 0;

        CreateNewNoncePool(s);
        fNoncePoolInitialsed = true;
    } else {
        s.nSleep = 3;
    }
}

static void handleInit(POCStateHolder& s)
{
    int nCount = 0;
    while (GetBoolArg("-cvnwaitforpeers", true) && vNodes.size() < 2 && !ShutdownRequested()) {
        if (!(nCount++ % 10))
            LogPrintf("Waiting for peers. Delaying to start the POC thread.\n");
        MilliSleep(1000);
    }

    s.nSleep = 2;

    if (mapCVNs.count(s.nNodeId)) {
        LOCK(cs_main);
        if (SetUpNoncePool()) {
            LogPrintf("Using saved nonces pool\n");
            RelayNoncePool(mapNoncePool[s.nNodeId]);
        } else {
            fasito.vNonceHandles.clear();
            vNoncePrivate.clear();
            CreateNewNoncePool(s);
        }

        s.state = GetAdjustedTime() - s.pindexPrev->nTime > dynParams.nBlockSpacing + dynParams.nBlockSpacingGracePeriod ?
                    CREATE_SIGNATURE_OVERDUE : WAITING_FOR_BLOCK_PROPAGATION;
        fNoncePoolInitialsed = true;
    } else {
        LogPrintf("Your node (0x%08x) has been removed from the network.\n", s.nNodeId);
        s.state = WAITING_FOR_CVN_DATA;
        return;
    }
}

static void (*stateHandlers[])(POCStateHolder& s) = {
        handleInit,
        handleWaitingForBlockPropagation,
        handleCreateSignature,
        handleWaitingForSignatures,
        handleWaitingForBlock,
        handleWaitingForNewTip,
        handleWaitingForCvnData,
        handleCompleteSignatureSets,
        handleCreateSignature,
        handleWaitingForSignatures,
};

void static POCThread(const CChainParams& chainparams, const uint32_t& nNodeId)
{
    POCState lastState = WAITING_FOR_NEW_TIP;

    SetThreadPriority(THREAD_PRIORITY_NORMAL);
    RenameThread("CVN-PoC");

    CReserveScript feeScript;

    if (!GetFeeScript(feeScript)) {
        LogPrintf("Invalid fee address supplied. Can NOT start CVN!\n");
        return;
    }

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

    POCStateHolder s(INIT, nNextCreator, chainActive.Tip(), nNodeId, chainparams, feeScript);

    LogPrintf("POC thread started for node ID 0x%08x\n", nNodeId);

    try {
        while (!ShutdownRequested()) {
            s.pindexPrev = chainActive.Tip();
            s.nNextCreator = CheckNextBlockCreator(s.pindexPrev, GetAdjustedTime());

            if (!s.nNextCreator) { // should not happen! And if it did, behave nice
                MilliSleep(2000);
                continue;
            }

            if (s.state != WAITING_FOR_CVN_DATA) {
                if ((s.NewTip())) {
                    LogPrintf("POCThread new tip detected. Next creator: 0x%08x\n", s.nNextCreator);
                    s.Reset(s.nNextCreator, s.pindexPrev, WAITING_FOR_BLOCK_PROPAGATION);
                    sigHolder.clear(s.nNextCreator);
                    lastState = UNDEFINED; // force print the new state
                } else if (s.BlockSpacingTimeout()) {
                    LogPrintf("POCThread block spacing timeout detected. Next creator: 0x%08x\n", s.nNextCreator);
                    s.Reset(s.nNextCreator, s.pindexPrev, CREATE_SIGNATURE_OVERDUE);
                    sigHolder.clear(s.nNextCreator);
                    lastState = UNDEFINED; // force print the new state
                }
            }

            if (s.state >= UNDEFINED) {
                LogPrintf("invalid state detected. Exiting POC thread.");
                break;
            }

            stateHandlers[s.state](s);

            if (s.nSleep) {
                while (s.nSleep-- && !ShutdownRequested())
                    MilliSleep(1000);
                s.nSleep = 0;
            } else
                MilliSleep(1000);

            if (s.state != lastState) {
                LogPrintf("POCThread state: %s\n", pocStateNames[s.state]);
                lastState = s.state;
            }
        }

        LogPrintf("POC thread stopped\n");
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("POC thread terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("POC Thread runtime error: %s\n", e.what());
        return;
    }
}

void RunPOCThread(const bool fGenerate, const CChainParams& chainparams, const uint32_t& nNodeId)
{
    static boost::thread_group* pocThread = NULL;

    if (pocThread != NULL) {
        pocThread->interrupt_all();
        delete pocThread;
        pocThread = NULL;

        return;
    }

    if (!fGenerate)
        return;

    if (!nNodeId) {
        LogPrintf("Not starting POC thread. CVN not configured.\n");
        return;
    }

    pocThread = new boost::thread_group();
    pocThread->create_thread(boost::bind(&POCThread, boost::cref(chainparams), boost::cref(nNodeId)));
}
#endif // USE_CVN
