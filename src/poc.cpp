// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockfactory.h>
#include "consensus/consensus.h"
#include "util.h"
#include "poc.h"
#include "main.h"
#include "timedata.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "net.h"
#include "init.h"
#include "cvn.h"
#include "clientversion.h"
#include "validationinterface.h"

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

CvnInfoCacheType mapCVNInfoCache;

CCriticalSection cs_mapChainAdmins;
ChainAdminMapType mapChainAdmins;

CCriticalSection cs_mapCVNs;
CvnMapType mapCVNs;

CCriticalSection cs_mapNoncePool;
CNoncePoolType mapNoncePool;

CCriticalSection cs_mapChainData;
ChainDataMapType mapChainData;

CCriticalSection cs_mapBlockIndexByPrevHash;
BlockIndexByPrevHashType mapBlockIndexByPrevHash;

CCriticalSection cs_mapBannedCVNs;
BannedCVNMapType mapBannedCVNs;

/* private nonces when starting faircoind with -cvn=file */
static vector<CSchnorrPrivNonce> vNoncePrivate;
static secp256k1_context *secp256k1_context_none = NULL;

const char *pocStateNames[] = {
        "INIT",
        "NONCE_POOL_CHANGES",
        "CREATE_SIGNATURE",
        "WAITING_FOR_SIGNATURES",
        "WAITING_FOR_BLOCK",
        "WAITING_FOR_NEW_TIP",
        "WAITING_FOR_CVN_DATA",
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

static bool GetCvnInfoCache(CvnInfoCache **cache, const uint32_t nHeight)
{
    if (mapCVNInfoCache.empty()) {
        LogPrintf("GetCvnInfoCache : fatal, CVN info cache is empty\n");
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
        LogPrintf("could not find CVN information\n");
        return 0;
    }

    return info->nActiveCvns - pindex->vMissingSignerIds.size();
}

uint32_t GetNumChainSigs(const CBlock *pblock)
{
    BlockMap::iterator miPrev = mapBlockIndex.find(pblock->hashPrevBlock);
    if (miPrev == mapBlockIndex.end()) {
        LogPrintf("GetNumChainSigs : prev block not found in block index: %s\n", pblock->hashPrevBlock.ToString());
        return 0;
    }

    CBlockIndex *pindexPrev = (*miPrev).second;
    CvnInfoCache *info;
    if (!GetCvnInfoCache(&info, pindexPrev->nHeight + 1)) {
        LogPrintf("could not find CVN information\n");
        return 0;
    }

    return info->nActiveCvns - pblock->vMissingSignerIds.size();
}

static const string CreateSignerIdList(const std::vector<uint32_t>& vNodeIds)
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

static bool GetFeeScript(CReserveScript &script)
{
#ifdef ENABLE_WALLET
    GetMainSignals().FeeScript(script);
#else
    if (!mapArgs.count("-cvnfeeaddress")) {
        LogPrintf("Option -cvnfeeaddress must be given if wallet support is not compiled in.\n");
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
            LogPrintf("CVN ERROR: the fee address %s is invalid. Falling back to standard wallet address.\n", feeAddress.ToString());
#else
            LogPrintf("CVN ERROR: the fee address %s is invalid. Can not start CVN.\n", feeAddress.ToString());
            return false;
#endif
        }
    }

    return true;
}

void CvnInfoCache::SetNull()
{
    nActiveCvns = 0;
    memset(sumOfAllpubKeys.data, 0, sizeof(sumOfAllpubKeys.data));
}

void CSignatureHolder::AddSig(const CCvnPartialSignature &sig)
{
    LOCK(cs_sigHolder);

    MapSigCreator& mapCreator = mapTip[sig.hashPrevBlock];
    MapSigCommonR& mapCommonR = mapCreator[sig.nCreatorId];
    MapSigSigner& mapSigner   = mapCommonR[sig.signature.GetRx()];

    mapSigner[sig.nSignerId]  = sig;
}

MapSigSigner* CSignatureHolder::GetSignatureSet(const CSchnorrRx &commonRx, const uint256 &hashPrevBlock, const uint32_t nNextCreator)
{
    if (!mapTip.count(hashPrevBlock)) {
        LogPrintf("GetSignatureSet : no hashPrevBlock=%s, mapTip.size=%u\n", hashPrevBlock.ToString(), mapTip.size());
        return NULL;
    }

    MapSigCreator& mapCreator = mapTip[hashPrevBlock];
    if (!mapCreator.count(nNextCreator)) {
        LogPrintf("GetSignatureSet : no nNextCreator=%08x, mapMissing.size=%u\n", nNextCreator, mapCreator.size());
        return NULL;
    }

    MapSigCommonR& mapCommonR = mapCreator[nNextCreator];
    if (!mapCommonR.count(commonRx)) {
        LogPrintf("GetSignatureSet : no commonRx=%s, mapCommonR.size=%u\n", commonRx.ToString(), mapCommonR.size());

        BOOST_FOREACH(const MapSigCommonR::value_type& entry, mapCommonR)
        {
            LogPrintf("  : %s\n", entry.first.ToString());
        }

        return NULL;
    }

    MapSigSigner& mapSigner = mapCommonR[commonRx];
    if (mapSigner.empty()) {
        LogPrintf("GetSignatureSet : no commonRx=%s, mapSigner.size=%u\n", commonRx.ToString(), mapSigner.size());
        return NULL;
    }

    return &mapCommonR[commonRx];
}

CCvnPartialSignature* CSignatureHolder::GetSignature(const uint256 &hashPrevBlock, const uint32_t nNextCreator, const uint32_t nSignerId, const CSchnorrRx &commonRx)
{
    if (!mapTip.count(hashPrevBlock))
        return NULL;

    MapSigCreator& mapCreator = mapTip[hashPrevBlock];
    if (!mapCreator.count(nNextCreator))
        return NULL;

    MapSigCommonR& mapCommonR = mapCreator[nNextCreator];
    if (!mapCommonR.count(commonRx))
        return NULL;

    MapSigSigner& mapSigner = mapCommonR[commonRx];

    if (!mapSigner.count(nSignerId))
        return NULL;

    return &mapSigner[nSignerId];
}

bool CSignatureHolder::GetSignatures(vector<CCvnPartialSignature> &sigs, const uint256 &hashPrevBlock, const uint32_t nNextCreator)
{
    if (mapTip.empty() || !mapTip.count(hashPrevBlock))
        return false;

    MapSigCreator& mapCreator = mapTip[hashPrevBlock];
    if (!mapCreator.count(nNextCreator))
        return false;

    MapSigCommonR& mapCommonR = mapCreator[nNextCreator];
    if (mapCommonR.empty())
        return false;

    MapSigSigner& mapSigner = mapCommonR.begin()->second;
    if (mapSigner.empty())
        return false;

    BOOST_FOREACH(const MapSigCommonR::value_type &entry, mapCommonR) {
        BOOST_FOREACH(const MapSigSigner::value_type &s, entry.second) {
            sigs.push_back(s.second);
        }
    }

    return !sigs.empty();
}

MapSigCommonR* CSignatureHolder::GetCommonR(const uint256 &hashPrevBlock, const uint32_t nNextCreator)
{
    if (mapTip.empty() || !mapTip.count(hashPrevBlock))
        return NULL;

    MapSigCreator& mapCreator = mapTip[hashPrevBlock];
    if (!mapCreator.count(nNextCreator))
        return NULL;

    return &mapCreator[nNextCreator];
}


string CSignatureHolder::ToString()
{
    std::stringstream s;

    LOCK(cs_sigHolder);
    BOOST_FOREACH(const MapSigTip::value_type& tip, mapTip) {
        s << strprintf("tip           (%02d): %s\n", mapTip.size(), tip.first.ToString());
        BOOST_FOREACH(const MapSigCreator::value_type& creator, tip.second) {
            s << strprintf(" next creator (%02d): 0x%08x\n", creator.second.size(), creator.first);
            BOOST_FOREACH(const MapSigCommonR::value_type& commonRx, creator.second) {
                s << strprintf("  commonRx    (%02d): %s\n", commonRx.second.size(), commonRx.first.ToString());
                BOOST_FOREACH(const MapSigSigner::value_type& signer, commonRx.second) {
                    s << strprintf("   signer         : 0x%08x (%s)\n", signer.first, signer.second.ToString());
                }
            }
        }
    }

    return s.str();
}

void CSignatureHolder::flushOldEntries(const uint256 &hashPrevBlock, const uint32_t nNextCreator)
{
    LOCK(cs_sigHolder);

    if (mapTip.empty() || !mapTip.count(hashPrevBlock))
        return;

    MapSigCreator& mapCreator = mapTip[hashPrevBlock];

    BOOST_FOREACH(MapSigCreator::value_type &creator, mapCreator) {
        if (creator.first != nNextCreator) {
            MapSigCommonR &missing = creator.second;
            missing.clear();
        }
    }
}

CSignatureHolder sigHolder;

static MapSigSigner* GetSignatureSet(POCStateHolder& s)
{
    AssertLockHeld(sigHolder.cs_sigHolder);
    return sigHolder.GetSignatureSet(s.commonRx, s.GetPrevBlockHash(), s.nNextCreator);
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

bool static CreateNonceWithKey(const uint256& hashData, const CKey& cvnPrivKey, unsigned char *pPrivateData, CSchnorrNonce& noncePublic, const CCvnInfo& cvnInfo)
{
    if (cvnInfo.pubKey != cvnPubKey) {
        LogPrintf("CreateNonceWithKey : key does not match node ID\n"
                "  block chain pubkey: %s\n"
                "  FASITO/FILE pubkey: %s\n", cvnInfo.pubKey.ToString(), cvnPubKey.ToString());
        return false;
    }

    CHashWriter hasher(SER_GETHASH, 0);
    hasher << GetTimeMillis() << string("we need random nonces") << rand();

    if (!cvnPrivKey.SchnorrCreateNoncePair(hashData, noncePublic, pPrivateData, hasher.GetHash())) {
        LogPrintf("CreateNonceWithKey : could not create block signature\n");
        return false;
    }

#if POC_DEBUG
    LogPrintf("CreateNonceWithKey : OK\n  Hash: %s\n  pubk: %s\n  pubn: %s\n privn: %s\n",
            hashData.ToString(),
            cvnInfo.pubKey.ToString(),
            noncePublic.ToString(),
            HexStr(pPrivateData));
#endif
    return true;
}

static bool CreateNoncePairForHash(CSchnorrNonce& noncePublic, unsigned char *pPrivateData, const uint256& hashToSign, const uint32_t& nNodeId, const bool fUseFasito)
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

    CCvnInfo cvnInfo = mapCVNs[nNodeId];

    if (fUseFasito) {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrint("cvn", "CreateNoncePairForHash : Fasito is not ready.\n");
            return false;
        }
        if (!CreateNonceWithFasito(hashToSign, fasito.nCVNKeyIndex, pPrivateData, noncePublic, cvnInfo)) {
            noncePublic.SetNull();
            return false;
        }
#else
        LogPrintf("CreateNoncePairForHash : ERROR, this wallet was not compiled with Fasito support\n");
        return false;
#endif
    } else {
        if (!CreateNonceWithKey(hashToSign, cvnPrivKey, pPrivateData, noncePublic, cvnInfo)) {
            noncePublic.SetNull();
            return false;
        }
    }

    return true;
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

bool static CvnSignPartialWithKey(const uint256& hashToSign, const CKey& cvnPrivKey, const CSchnorrPubKey& sumPublicNoncesOthers, CCvnPartialSignatureUnsinged& signature)
{
    int nPoolOffset = chainActive.Tip()->nHeight - mapNoncePool[nCvnNodeId].nHeightAdded;

    if (vNoncePrivate[nPoolOffset].IsNull()) {
        LogPrintf("CvnSignPartialWithKey : could not create chain signature no private nonce available\n");
        return false;
    }

    if (!cvnPrivKey.SchnorrSignParial(hashToSign, sumPublicNoncesOthers, vNoncePrivate[nPoolOffset], signature.signature)) {
        LogPrintf("CvnSignPartialWithKey : could not create chain signature\n");
        return false;
    }

#if POC_DEBUG
    LogPrintf("CvnSignPartialWithKey : OK\n  Hash: %s\nsigner: 0x%08x\n   sum: %s\n   sig: %s\n",
            hashToSign.ToString(), signature.nSignerId,
            sumPublicNoncesOthers.ToString(), signature.ToString());
#endif
    return true;
}

bool CvnSignHash(const uint256 &hashToSign, CSchnorrSig& signature)
{
    if (GetArg("-cvn", "") == "fasito") {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrintf("CreateNoncePairForHash : Fasito is not ready.\n");
            return false;
        }
        return CvnSignWithFasito(hashToSign, fasito.nCVNKeyIndex, signature);
#else
        LogPrintf("CvnSignHash : ERROR, this wallet was not compiled with smart card support\n");
        return false;
#endif
    } else {
        return CvnSignWithKey(hashToSign, cvnPrivKey, signature);
    }

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

bool CreateSumPublicNoncesOthers(CSchnorrPubKey &sumPublicNoncesOthers, const uint32_t& nNextCreator, const uint32_t& nNodeId, vector<uint32_t> &vMissingPubNonces, const vector<uint32_t> &vMissingCvnIds)
{
    LOCK(cs_mapNoncePool);
    vector<secp256k1_pubkey *> allPubOtherNonces;

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs) {
        if (cvn.first == nNodeId)
            continue;

        if (!mapNoncePool.count(cvn.first) || find(vMissingCvnIds.begin(), vMissingCvnIds.end(), cvn.first) != vMissingCvnIds.end()) {
            LogPrintf("CreateSumPublicNoncesOthers : 0x%08x is missing\n", cvn.first);
            vMissingPubNonces.push_back(cvn.first);
            continue;
        }

        const CSchnorrNonce *nonce = GetCurrnetPublicNonce(cvn.first);
        if (nonce == NULL)
            continue;

        allPubOtherNonces.push_back((secp256k1_pubkey *)nonce);
    }

    memset(&sumPublicNoncesOthers.begin()[0], 0, 64);
    if (allPubOtherNonces.size() > 1) {
        if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, (secp256k1_pubkey *)&sumPublicNoncesOthers.begin()[0], &allPubOtherNonces[0], allPubOtherNonces.size())) {
            LogPrintf("CreateSumPublicNoncesOthers : could not combine nonces\n");
            return false;
        }
    } else if (allPubOtherNonces.size() == 1) {
        memcpy(&sumPublicNoncesOthers.begin()[0], allPubOtherNonces[0], 64);
    } else {
        LogPrintf("CreateSumPublicNoncesOthers : ERROR: no nonces avaialbe\n");
        return false;
    }

    return true;
}

bool CvnSignPartial(const uint256 &hashPrevBlock, CCvnPartialSignatureUnsinged &signature, const uint32_t &nNextCreator, const uint32_t &nNodeId, const vector<uint32_t> &vMissingCvnIds)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashPrevBlock << nNextCreator;

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

    signature.nSignerId     = nNodeId;
    signature.nCreatorId    = nNextCreator;
    signature.hashPrevBlock = hashPrevBlock;

    /* create a plain schnorr signature in case only one CVN is available (e.g. during bootstrap) */
    if (mapCVNs.size() == 1)
        return CvnSignHash(hasher.GetHash(), signature.signature);

    CSchnorrPubKey sumPublicNoncesOthers;
    vector<uint32_t> vMissingPubNonces;
    if (!CreateSumPublicNoncesOthers(sumPublicNoncesOthers,  nNextCreator, nNodeId, vMissingPubNonces, vMissingCvnIds))
        return false;

    if (!vMissingPubNonces.empty()) {
        /* if we have missing signers we modify the hashToSign to avoid that
         * that we sign the same message with a different set of nonces */
        BOOST_FOREACH(const uint32_t& nMissingId, vMissingPubNonces) {
            hasher << nMissingId;
        }
    }

    uint256 hashToSign = hasher.GetHash();

    if (GetArg("-cvn", "") == "fasito") {
#ifdef USE_FASITO
        if (!fasito.fLoggedIn) {
            LogPrint("cvn", "CvnSignPartial : ERROR, smart card not unlocked. Make sure that -cvnpin, -cvnslot and -cvnkeyid are set correctly\n");
            return false;
        }

        if (!CvnSignPartialWithFasito(hashToSign, fasito.nCVNKeyIndex, sumPublicNoncesOthers, signature, chainActive.Tip()->nHeight))
            return false;
#else
        LogPrintf("CvnSignPartial : ERROR, this wallet was not compiled with smart card support\n");
        return false;
#endif
    } else {
        if (!CvnSignPartialWithKey(hashToSign, cvnPrivKey, sumPublicNoncesOthers, signature))
            return false;
    }

    signature.vMissingSignerIds = vMissingPubNonces;

    return CvnVerifyPartialSignature(hashToSign, signature.signature, mapCVNs[nNodeId].pubKey, sumPublicNoncesOthers);
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

    if (!CvnSignHash(block.GetCreatorHash(), block.creatorSignature))
        return false;

    return true;
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
        BlockMap::iterator mi = mapBlockIndex.find(block.GetHash());
        if (mi == mapBlockIndex.end())
            return false;

        CvnInfoCache *cache;
        GetCvnInfoCache(&cache, (*mi).second->nHeight);
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

        BOOST_FOREACH(const uint32_t& nMissingId, vMissingSignersIds) {
            hasher << nMissingId;
        }
    }

    uint256 hash = hasher.GetHash();

    CSchnorrPubKey pubKey(sumOfAllSignersPubkeys.data);
    if (!CvnVerifySignature(hash, block.chainMultiSig, pubKey))
        return error("CvnVerifyChainSignature : could not verify chain signature for block %s: %s (missing: %d)", hash.ToString(), block.chainMultiSig.ToString(), block.vMissingSignerIds.size());

    return true;
}

bool CvnVerifySignature(const uint256 &hash, const CSchnorrSig &sig, const CSchnorrPubKey &pubKey)
{
    if (!CPubKey::VerifySchnorr(hash, sig, pubKey))
        return false;

    return true;
}

bool CvnVerifyPartialSignature(const uint256 &hash, const CSchnorrSig &sig, const CSchnorrPubKey &pubKey, const CSchnorrPubKey &sumPublicNoncesOthers)
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

    LogPrintf("%s\n", msg.ToString());
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

bool CvnVerifyPartialSignature(const CCvnPartialSignature& sig)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << sig.hashPrevBlock << sig.nCreatorId;

    if (!mapCVNs.count(sig.nCreatorId)) {
        LogPrintf("CvnVerifyPartialSignature : next creator CVN not found 0x%08x\n", sig.nCreatorId);
        return false;
    }

    if (!mapCVNs.count(sig.nSignerId)) {
        LogPrintf("CvnVerifyPartialSignature : signer CVN not found 0x%08x\n", sig.nSignerId);
        return false;
    }

    if (mapCVNs.size() == 1)
        return CvnVerifySignature(hasher.GetHash(), sig.signature, sig.nSignerId);

    CSchnorrPubKey sumPublicNoncesOthers;
    vector<uint32_t> vMissingPubNonces;
    if (!CreateSumPublicNoncesOthers(sumPublicNoncesOthers, sig.nCreatorId, sig.nSignerId, vMissingPubNonces, sig.vMissingSignerIds))
        return false;

    if (vMissingPubNonces != sig.vMissingSignerIds){
        LogPrintf("CvnVerifyPartialSignature : missingPubNonces mismatch: %s (%d != %d)\n", sig.ToString(), vMissingPubNonces.size(), sig.vMissingSignerIds.size());
        return false;
    }

    if (!vMissingPubNonces.empty()) {
        /* if we have missing signers we modify the hashToSign to avoid that
         * that we sign the same message with a different set of nonces */
        BOOST_FOREACH(const uint32_t& nMissingId, vMissingPubNonces) {
            hasher << nMissingId;
        }
    }

    return CvnVerifyPartialSignature(hasher.GetHash(), sig.signature, mapCVNs[sig.nSignerId].pubKey, sumPublicNoncesOthers);
}

bool AddCvnSignature(CCvnPartialSignature& msg)
{
    if (!CvnVerifySignature(msg.GetHash(), msg.msgSig, msg.nSignerId))
        return false;

    msg.fValidated = CvnVerifyPartialSignature(msg);
    if (!msg.fValidated)
        LogPrintf("AddCvnSignature : invalid signature received for 0x%08x by 0x%08x, hash %s. Marked as invalid.\n", msg.nCreatorId, msg.nSignerId, msg.hashPrevBlock.ToString());

    sigHolder.AddSig(msg);

    LogPrint("cvnsig", "AddCvnSignature : add sig for 0x%08x by 0x%08x, hash %s, missing: %s\n", msg.nCreatorId, msg.nSignerId,
            msg.hashPrevBlock.ToString(),
            (msg.vMissingSignerIds.empty() ? "none" : CreateSignerIdList(msg.vMissingSignerIds)));

    return true;
}

bool SendCVNSignature(POCStateHolder &s)
{
    if (IsInitialBlockDownload())
        return false;

    const CBlockIndex *pTip = s.pindexPrev;
    uint32_t nNextCreator = CheckNextBlockCreator(pTip, GetAdjustedTime());

    if (!nNextCreator) {
        LogPrintf("SendCVNSignature : could not find next block creator\n");
        return false;
    }

    uint256 hashPrevBlock = pTip->GetBlockHash();

    CCvnPartialSignatureUnsinged signature;
    if (!CvnSignPartial(hashPrevBlock, signature, nNextCreator, nCvnNodeId, s.vMissingSignatures)) {
        LogPrintf("SendCVNSignature : could not create sig for 0x%08x by 0x%08x, hash %s\n",
                nNextCreator, nCvnNodeId, hashPrevBlock.ToString());
        return false;
    }

    CCvnPartialSignature msg(signature);

    CSchnorrSig msgSig;
    if (!CvnSignHash(msg.GetHash(), msgSig)) {
        LogPrintf("SendCVNSignature : could not sign signature message\n");
        return false;
    }

    msg.msgSig = msgSig;

    if (AddCvnSignature(msg))
        RelayCvnSignature(msg);

    s.vMissingSignatures = msg.vMissingSignerIds;
    s.commonRx = msg.signature.GetRx();

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

    LOCK(cs_mapCVNs);

    mapCVNs.clear();
    int count = 0;
    secp256k1_pubkey *allSignersPubkeys[MAX_NUMBER_OF_CVNS];

    BOOST_FOREACH(const CCvnInfo &cvnInfo, pblock->vCvns) {
        mapCVNs.insert(std::make_pair(cvnInfo.nNodeId, cvnInfo));
        allSignersPubkeys[count++] = (secp256k1_pubkey *)&cvnInfo.pubKey.begin()[0];
    }

    secp256k1_pubkey sumOfAllSignersPubkeys;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_none, &sumOfAllSignersPubkeys, allSignersPubkeys, count))
        LogPrintf("could not combine signers public keys");

    mapCVNInfoCache[nHeight] = CvnInfoCache(sumOfAllSignersPubkeys, mapCVNs.size());

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

bool CheckProofOfCooperation(const CBlock& block, const Consensus::Params& params)
{
    uint256 hashBlock = block.GetHash();

    if (!CheckForDuplicateMissingChainSigs(block))
        return false;

    if (!CvnVerifyChainSignature(block))
        return false;

    BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
    if (mi == mapBlockIndex.end()) {
        if (hashBlock != params.hashGenesisBlock) {
            LogPrint("cvn", "CheckProofOfCooperation : can not check orphan block %s created by 0x%08x, delaying check.\n",
                        hashBlock.ToString(), block.nCreatorId);
            return false;
        } else
            return true;
    }

    // check if creator ID matches consensus rules
    uint32_t nBlockCreator = CheckNextBlockCreator(mapBlockIndex[block.hashPrevBlock], block.nTime);

    if (!nBlockCreator)
        return error("CheckProofOfCooperation : FATAL: can not determine block creator for %s", hashBlock.ToString());

    if (nBlockCreator != block.nCreatorId)
        return error("CheckProofOfCooperation : block %s can not be created by 0x%08x but by 0x%08x", hashBlock.ToString(), block.nCreatorId, nBlockCreator);


    CBlockIndex* pindexPrev = (*mi).second;
    uint32_t nChainSigs = GetNumChainSigs(&block);
    uint32_t nPrevChainSigs = GetNumChainSigs(pindexPrev);

    if (!nChainSigs || !nPrevChainSigs) {
        LogPrintf("CheckProofOfCooperation : could not determine number of signatures: %d|%d\n", nChainSigs, nPrevChainSigs);
        return false;
    }

    LogPrint("cvn", "CheckProofOfCooperation : checking # sigs (prev: %u, this: %u) of block %s created by 0x%08x\n",
            nPrevChainSigs, nChainSigs, hashBlock.ToString(), block.nCreatorId);

    // only do advanced checks if we have a decrease in the number of signatures
    if (nPrevChainSigs > nChainSigs) {
        // this block requires at least dynParams.nPercentageOfSignatureMean of the number of nSignatureMean
        if (!HasEnoughSignatures(pindexPrev, nChainSigs)) {
            LogPrintf("CheckProofOfCooperation : past signatures [");
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
        LogPrintf("CheckNextBlockCreator : CVN 0x%08x needs to be bootstrapped\n", nNextCreatorId);
        vCreatorCandidates.push_back(nNextCreatorId);
    } else if (vCreatorCandidates.size() < nRegisteredCVNs) {
        nNextCreatorId = FindDormantNode(pindexStart, mapLastSignatures, setCreatorCandidates, dynParams.nMinSuccessiveSignatures);

        if (nNextCreatorId) {
            LogPrintf("CheckNextBlockCreator : dormant CVN 0x%08x detected - activating...\n", nNextCreatorId);
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
        //LogPrintf("CheckNextBlockCreator : WARN, CandidateOffset exceeds limits: %u >= %u\n", nCandidateOffset, vCreatorCandidates.size());
        nCandidateOffset %= vCreatorCandidates.size();
        //LogPrintf("CheckNextBlockCreator : reducing offset to %u\n", nCandidateOffset);
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

static int32_t GetPoolAge(const CNoncePool &pool, CBlockIndex *pTip)
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
        LogPrintf("AddNoncePool : could not determine pool age. CvnID 0x%08x, hash %s, size: %d\n", msg.nCvnId, msg.hashRootBlock.ToString(), nSize);
        return false;
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
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelayNonces.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        mapRelayNonces.insert(std::make_pair(inv.hash, msg));
        // we keep them around for 5h so AlreadyHave() works properly
        vRelayExpiration.push_back(std::make_pair(GetTime() + 18000, inv.hash));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayTxes) // same TX rules apply to pub nonce messages
            continue;

        pnode->PushInventory(inv);
    }
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
    if (!pooldb.Read(pool, vNoncePrivate, vNonceHandles))
        return false;

    if (fUseFasito && vNonceHandles.size() != pool.vPublicNonces.size()) {
        LogPrintf("SetUpNoncePool : number of private handle/public nonces mismatch: %d/%d\n", vNonceHandles.size(), pool.vPublicNonces.size());
        vNonceHandles.clear();
        return false;
    }

    if (!fUseFasito && vNoncePrivate.size() != pool.vPublicNonces.size()) {
        LogPrintf("SetUpNoncePool : number of private/public nonces mismatch: %d/%d\n", vNoncePrivate.size(), pool.vPublicNonces.size());
        vNoncePrivate.clear();
        return false;
    }

    {
        LOCK(cs_mapNoncePool);
        mapNoncePool.erase(pool.nCvnId);
    }
    return AddNoncePool(pool);
}

static bool CreateNoncePoolFile(CNoncePool& pool, const uint16_t nPoolSize)
{
    const uint256 hash4noncePool = pool.GetHash();

    vNoncePrivate.clear();
    for (uint16_t i = 0 ; i < nPoolSize ; i++) {
        CSchnorrNonce nonce;
        unsigned char privateData[32];
        if (!CreateNoncePairForHash(nonce, privateData, hash4noncePool, pool.nCvnId, false)) {
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
static bool CreateNoncePoolFasito(CNoncePool& pool, const uint16_t nPoolSize)
{
    const uint256 hash4noncePool = pool.GetHash();

    fasito.vNonceHandles.clear();
    if (!fasito.sendCommand("CLRPOOL")) {
        LogPrintf("could not clear nonce pool on Fasito\n");
        return false;
    }

    for (uint16_t i = 0 ; i < nPoolSize ; i++) {
        CSchnorrNonce nonce;
        unsigned char privateData[32];
        if (!CreateNoncePairForHash(nonce, privateData, hash4noncePool, pool.nCvnId, true)) {
            pool.vPublicNonces.clear();
            return false;
        }

        uint32_t *nHandle = (uint32_t *) &privateData[0];
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

    if (GetArg("-cvn", "") == "file") {
        CreateNoncePoolFile(pool, nPoolSize);
    }
#ifdef USE_FASITO
    else {
        CreateNoncePoolFasito(pool, nPoolSize);
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

    if (AddNoncePool(pool)) {
        SaveNoncesPool();
        RelayNoncePool(pool);
    }
}

static void handleCreateSignature(POCStateHolder& s)
{
    CCvnPartialSignature *sig = NULL;

    {
        LOCK(sigHolder.cs_sigHolder);
        sig = sigHolder.GetSignature(s.GetPrevBlockHash(), s.nNextCreator, s.nNodeId, s.commonRx);
    }

    if (!sig) {
        if (SendCVNSignature(s)) {
            s.state  = WAITING_FOR_SIGNATURES;
            if (GetAdjustedTime() - s.pindexPrev->nTime > dynParams.nBlockSpacing)
                s.nSleep = 10;
        }
    } else
        s.state  = WAITING_FOR_SIGNATURES;
}

static void handleWaitingForSignatures(POCStateHolder& s)
{
    LOCK(sigHolder.cs_sigHolder);

    MapSigSigner *sigs = GetSignatureSet(s);
    if (sigs && sigs->size() == mapNoncePool.size() - s.vMissingSignatures.size()) {
        s.state = WAITING_FOR_BLOCK;
        return;
    }

    int32_t nLastBlockSeconds = GetAdjustedTime() - s.pindexPrev->nTime;

    if ((nLastBlockSeconds > (int32_t)(dynParams.nBlockSpacing / 3) + NONCE_POOL_WAIT_TIME && nLastBlockSeconds < (int32_t)dynParams.nBlockSpacing) ||
            (nLastBlockSeconds >= (int32_t)dynParams.nBlockSpacing && s.vMissingSignatures.empty())) {
        //TODO: for debugging only, remove...
        if (sigs && !sigs->count(s.nNodeId)) {
            LogPrintf("---------> SHOULD NOT HAPPEN: sigs.size()=%u\n%s\n", sigs->size(), sigHolder.ToString());
            BOOST_FOREACH(const MapSigSigner::value_type& sDebug, *sigs) {
                LogPrintf(" :: %08x != %08x\n", sDebug.first, s.nNodeId);
            }
            s.state = CREATE_SIGNATURE;
            return;
        }
        
        /* We have not received all the expected partial signatures.
         * Find the missing node and re-try without it. */
        BOOST_FOREACH(const CNoncePoolType::value_type& p, mapNoncePool) {
            if (sigs && sigs->count(p.first))
                continue;

            s.vMissingSignatures.push_back(p.first);
        }

        if (!s.vMissingSignatures.empty()) {
            s.commonRx.SetNull();
            if (HasEnoughSignatures(s.pindexPrev, mapCVNs.size() - s.vMissingSignatures.size())) {
                s.state = CREATE_SIGNATURE;
            }
        }
        LogPrintf("Did not receive all sigs for set. Trying signature set with reduced number of members: %d/%d\n", mapCVNs.size() - s.vMissingSignatures.size(), mapCVNs.size());
    } else if (nLastBlockSeconds >= (int32_t)dynParams.nBlockSpacing) {
        if (s.nNextCreator == s.nNodeId) {
            CBlock dummy;
            dummy.nCreatorId = s.nNextCreator;
            dummy.hashPrevBlock = s.GetPrevBlockHash();
            LogPrintf("Trying to create block immediately.\n");
            if (DetermineBestSignatureSet(s.pindexPrev, &dummy)) {
                if (CreateBlock(s)) {
                    s.state = WAITING_FOR_NEW_TIP;
                }
            } else {
                LogPrintf("Unable to find any usable signature set!\n");
                s.nSleep = 4;
            }
        }
    }
}

static void handleWaitingForBlock(POCStateHolder& s)
{
    if (s.NewTip())
        s.Reset(s.nNextCreator, chainActive.Tip());

    if (s.nNextCreator == s.nNodeId && GetSignatureSet(s)) {
        int32_t nBlockTime = GetAdjustedTime() - s.pindexPrev->nTime;
        uint32_t nSigs = GetNumChainSigs(s.pindexLastTip);
        if (nBlockTime >= (int32_t)dynParams.nBlockSpacing && HasEnoughSignatures(s.pindexPrev, nSigs - s.vMissingSignatures.size())) {
            if (CreateBlock(s)) {
                s.state = WAITING_FOR_NEW_TIP;
            }
        }
    }
}

static void handleWaitingForNewTip(POCStateHolder& s)
{
    if (s.NewTip())
        s.Reset(s.nNextCreator, chainActive.Tip());

    return;
}

static void handleNoncePoolChanges(POCStateHolder& s)
{
    if (!mapCVNs.count(s.nNodeId)) {
        LogPrintf("Your node (0x%08x) has been removed from the network.\n", s.nNodeId);
        s.state = WAITING_FOR_CVN_DATA;
        return;
    }

    if (GetAdjustedTime() - s.pindexPrev->nTime <= NONCE_POOL_WAIT_TIME + 5)
        s.nSleep = NONCE_POOL_WAIT_TIME + (rand() % 10) - 5;
    else
        s.nSleep = 5;

    if (mapNoncePool.count(s.nNodeId)) {
        const CNoncePool &p = mapNoncePool[s.nNodeId];
        const uint32_t nPoolAge = GetPoolAge(p, s.pindexPrev);

        if (nPoolAge + 1 >= p.vPublicNonces.size()) {
            LogPrint("cvnsig", "nonce pool expired, creating new pool.\n");
            CreateNewNoncePool(s);
        }
    }

    {
        LOCK(cs_mapNoncePool);

        CNoncePoolType::iterator it = mapNoncePool.begin();
        while (it != mapNoncePool.end()) {
            const pair<uint32_t, CNoncePool> &pt = *it;
            const CNoncePool &p = pt.second;
            const uint32_t nPoolAge = GetPoolAge(p, s.pindexPrev);
            const CNoncePoolType::iterator itErase = it++;

            if (nPoolAge >= p.vPublicNonces.size()) {
                LogPrintf("nonce pool expired, removing pool for 0x%08x.\n", pt.first);
                mapNoncePool.erase(itErase);
            }
        }
    }

    s.state = CREATE_SIGNATURE;
}

static void handleWaitingForCvnData(POCStateHolder& s)
{
    if (mapCVNs.count(s.nNodeId)) {
        LogPrintf("found CVN data for our node: %s\n", mapCVNs[s.nNodeId].ToString());
        s.state = NONCE_POOL_CHANGES;
        s.nSleep = 0;

        CreateNewNoncePool(s);
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
        if (SetUpNoncePool()) {
            LogPrintf("Using saved nonces pool\n");
            RelayNoncePool(mapNoncePool[s.nNodeId]);
        } else
            CreateNewNoncePool(s);

        s.state = NONCE_POOL_CHANGES;
        fNoncePoolInitialsed = true;
    } else {
        LogPrintf("Your node (0x%08x) has been removed from the network.\n", s.nNodeId);
        s.state = WAITING_FOR_CVN_DATA;
        return;
    }
}

static void (*stateHandlers[])(POCStateHolder& s) = {
        handleInit,
        handleNoncePoolChanges,
        handleCreateSignature,
        handleWaitingForSignatures,
        handleWaitingForBlock,
        handleWaitingForNewTip,
        handleWaitingForCvnData,
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

    // initialise random seed
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << chainActive.Tip()->GetBlockHash() << nNodeId << chainActive.Tip()->nHeight;
    srand((hasher.GetHash().GetCheapHash() >> 32) + GetTimeMillis());

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

            stateHandlers[s.state](s);

            if (s.nSleep) {
                while (s.nSleep-- && !ShutdownRequested())
                    MilliSleep(1000);
                s.nSleep = 0;
            } else
                MilliSleep(1000);

            if ((s.NewTip() || s.BlockSpacingTimeout()) && s.state != WAITING_FOR_CVN_DATA) {
                LogPrintf(s.NewTip() ? "new tip detected.\n" : "block spacing timeout detected.\n");
                s.Reset(s.nNextCreator, s.pindexPrev);
                sigHolder.flushOldEntries(s.GetPrevBlockHash(), s.nNextCreator);
            }

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
    static boost::thread_group* signerThreads = NULL;

    if (signerThreads != NULL) {
        signerThreads->interrupt_all();
        delete signerThreads;
        signerThreads = NULL;

        return;
    }

    if (!fGenerate)
        return;

    if (!nNodeId) {
        LogPrintf("Not starting POC thread. CVN not configured.\n");
        return;
    }

    signerThreads = new boost::thread_group();
    signerThreads->create_thread(boost::bind(&POCThread, boost::cref(chainparams), boost::cref(nNodeId)));
}
