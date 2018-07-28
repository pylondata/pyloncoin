// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2017 The Pyloncoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "primitives/cvn.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "key.h"
#include "keystore.h"
#include "init.h"
#include "wallet/wallet.h"
#include "base58.h"
#include "blockfactory.h"
#include "poc.h"
//#include "cvn.h"

#ifdef USE_FASITO
#include "fasito/fasito.h"
#endif

#include <secp256k1.h>
#include <secp256k1_schnorr.h>

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>
#include <map>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// C V N   -   Cooperatively Validated Node
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

static void PopulateBlock(CBlockTemplate& blocktemplate)
{
    CBlock *pblock = &blocktemplate.block; // pointer for convenience

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (blocktemplate.chainparams.CreateBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

    // Set block type TX_BLOCK
    pblock->nVersion |= CBlock::TX_PAYLOAD;

    // Create coinbase tx
    CMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = blocktemplate.feeScript.reserveScript;

    // Add dummy coinbase tx as first transaction
    CTransactionRef tx = MakeTransactionRef();
    pblock->vtx.push_back(tx);

    // Largest block we can create according to the dynamic chain parameters
    unsigned int nBlockMaxSize = dynParams.nMaxBlockSize - 7000;

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // This vector will be sorted into a priority queue:
    vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    std::priority_queue<CTxMemPool::txiter, std::vector<CTxMemPool::txiter>, ScoreCompare> clearedTxs;
    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    uint64_t nBlockSize = 1000;
    uint64_t nBlockTx = 0;
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = blocktemplate.pindexPrev;
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                                ? nMedianTimePast
                                : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock) {
            vecPriority.reserve(mempool.mapTx.size());
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                 mi != mempool.mapTx.end(); ++mi)
            {
                double dPriority = mi->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
                vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
            }
            std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        }

        CTxMemPool::indexed_transaction_set::nth_index<3>::type::iterator mi = mempool.mapTx.get<3>().begin();
        CTxMemPool::txiter iter;

        while (mi != mempool.mapTx.get<3>().end() || !clearedTxs.empty())
        {
            bool priorityTx = false;
            if (fPriorityBlock && !vecPriority.empty()) { // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty()) { // add tx with next highest score
                iter = mempool.mapTx.project<0>(mi);
                mi++;
            }
            else {  // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter))
                continue; // could have been added to the priorityBlock

            const CTransaction& tx = iter->GetTx();

            bool fOrphan = false;
            BOOST_FOREACH(CTxMemPool::txiter parent, mempool.GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent)) {
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan) {
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter,actualPriority));
                else
                    waitSet.insert(iter);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock &&
                (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) {
                fPriorityBlock = false;
                waitPriMap.clear();
            }
            if (nBlockSize + nTxSize >= nBlockMaxSize) {
                if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000) {
                    lastFewTxs++;
                }
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                continue;

            unsigned int nTxSigOps = iter->GetSigOpCost();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS) {
                if (nBlockSigOps > MAX_BLOCK_SIGOPS - 2) {
                    break;
                }
                continue;
            }

            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(MakeTransactionRef(tx));
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                double dPriority = iter->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(tx.GetHash(), dPriority, dummy);
                LogPrintf("priority %.1f fee %s txid %s\n",
                          dPriority , CFeeRate(iter->GetModifiedFee(), nTxSize).ToString(), tx.GetHash().ToString());
            }

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            BOOST_FOREACH(CTxMemPool::txiter child, mempool.GetMemPoolChildren(iter))
            {
                if (fPriorityBlock) {
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end()) {
                        vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else {
                    if (waitSet.count(child)) {
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }
        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("PopulateBlock : total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

        const CChainParams& chainparams = Params();

        // Compute final coinbase transaction. PoK reward (Proof Of Kilowatt)
         txNew.vout[0].nValue = nFees + GetBlockSubsidy(nHeight);
         std::string serverpylon = chainparams.GetPylonAddressServer(); //address pylon server
         CTxDestination ServerPylonDest = CBitcoinAddress(serverpylon).Get();
         CScript pylonCScript = GetScriptForDestination(ServerPylonDest);
         txNew.vout[0].scriptPubKey = pylonCScript;
         txNew.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(blocktemplate.nExtraNonce)) + COINBASE_FLAGS;
         assert(txNew.vin[0].scriptSig.size() <= 100);

        // don't spam the CVNs wallet with zero value transactions
        if (txNew.vout[0].nValue == 0) {
            txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;
            LogPrint("cvn", "creating OP_RETURN coinbase transaction for zero fee block\n");
        }

        pblock->vtx[0] = MakeTransactionRef(txNew);

        // Fill in header
        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    }
}

static bool ProcessRewardBlock(const CBlock* pblock, const CChainParams& chainparams)
{
    std::string serverpylon = chainparams.GetPylonAddressServer();
    CTxDestination ServerPylonDest = CBitcoinAddress(serverpylon).Get();
    CScript pylonCScript = GetScriptForDestination(ServerPylonDest);

    if (pblock->vtx[0]->vout[0].scriptPubKey != pylonCScript) {
    LogPrintf("RewardBlock: Address reward not match");
    return false;
     }else{
     return true;
     }

}

static bool ProcessCVNBlock(const CBlock* pblock, const CChainParams& chainparams)
{
    if (GetBoolArg("-printcreatedblock", true))
        LogPrintf("%s", pblock->ToString());

    LogPrintf("fees collected: %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue));

    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("CertifiedValidationNode: generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL))
        return error("CertifiedValidationNode: ProcessNewBlock, block not accepted");

    return true;
}

static bool AddChainDataToBlock(CBlock *pblock, const CChainDataMsg& msg)
{
    LogPrintf("adding chain admin data to block #%u: %s\n", chainActive.Tip()->nHeight + 1, msg.ToString());

    if (msg.vAdminIds.empty() || msg.adminMultiSig.IsNull() || !msg.nPayload) {
        LogPrintf("ERROR: no signatures available, payload: %u\n", msg.nPayload);
        return false;
    }

    if (msg.hashPrevBlock != pblock->hashPrevBlock) {
        LogPrintf("ERROR: chain data for different tip: %s != %s\n", msg.hashPrevBlock.ToString(), pblock->hashPrevBlock.ToString());
        return false;
    }

    pblock->vAdminIds     = msg.vAdminIds;
    pblock->adminMultiSig = msg.adminMultiSig;

    if (!CheckForDuplicateAdminSigs(*pblock)) {
        LogPrintf("found invalid admin sigs, ignoring admin payload.\n");
        pblock->vAdminIds.clear();
        pblock->adminMultiSig.SetNull();
        return true;
    }

    if (msg.HasCvnInfo()) {
        pblock->nVersion |= CBlock::CVN_PAYLOAD;
        pblock->vCvns = msg.vCvns;
    }

    if (msg.HasChainAdmins()) {
        pblock->nVersion |= CBlock::CHAIN_ADMINS_PAYLOAD;
        pblock->vChainAdmins = msg.vChainAdmins;
    }

    if (msg.HasChainParameters()) {
        if (CheckDynamicChainParameters(msg.dynamicChainParams)) {
            pblock->nVersion |= CBlock::CHAIN_PARAMETERS_PAYLOAD;
            pblock->dynamicChainParams = msg.dynamicChainParams;
        } else
            LogPrintf("received invalid chain parameter, ignoring it\n%s\n%s\n", msg.ToString(), msg.dynamicChainParams.ToString());
    }

    if (msg.HasCoinSupplyPayload()) {
        if (fCoinSupplyFinal) {
            LogPrintf("coin supply already final. Ignoring coin supply chain data\n%s\n%s\n", msg.ToString(), msg.coinSupply.ToString());
        } else {
            pblock->nVersion |= CBlock::COIN_SUPPLY_PAYLOAD;
            pblock->coinSupply = msg.coinSupply;

            CMutableTransaction tx(*pblock->vtx[0]);
            tx.vout.push_back(CTxOut(msg.coinSupply.nValue, msg.coinSupply.scriptDestination));

            pblock->vtx[0] = MakeTransactionRef(tx);
        }
    }

    return true;
}

typedef vector<vector<uint32_t> > MissingIdsCandidates;

bool DetermineBestSignatureSet(CBlockIndex * const pindexPrev, CBlock *pblock)
{
    LOCK(sigHolder.cs_sigHolder);

    if (sigHolder.sigs.empty()) {
        LogPrintf("Could not find signatures. Can not create block.\n");
        return false;
    }

    vector<CSchnorrSig> sigCandidates;
    MissingIdsCandidates vMissingSignerIdsCandidates;

    /* check each signature set. If it's correct and contains enough sigs remember it */
    BOOST_FOREACH(const MapSigCommonR::value_type& commonR, sigHolder.sigs) {
        MapSigSigner *signatures = sigHolder.GetSignatureSet(commonR.first);
        if (!signatures) {
            LogPrintf("No signatures found. Trying next set.\n");
            continue;
        }

        const CCvnPartialSignature &firstSig = commonR.second.begin()->second;
        if (signatures->size() + firstSig.vMissingSignerIds.size() < mapCVNs.size()) {
            LogPrintf("Not enough signatures found. Trying next set.\n");
            continue;
        }

        if (!HasEnoughSignatures(pindexPrev, signatures->size())) {
            LogPrintf("Not enough signatures to continue blockchain. Trying next set.\n");
            continue;
        }

        int count = 0;
        bool fAllSigsValid = true;
        uint8_t *sigs[MAX_NUMBER_OF_CVNS];
        set<uint32_t> setSigners;

        BOOST_FOREACH(const MapSigSigner::value_type& entry, *signatures) {
            const CCvnPartialSignature& sig = entry.second;

            if (!sig.fValidated && !CvnVerifyPartialSignature(sig)) {
                LogPrintf("Invalid signature found. Trying next set.\n%s\n", sig.ToString());
                fAllSigsValid = false;
                break;
            }

            if (!setSigners.insert(entry.first).second) {
                LogPrintf("duplicate signature detected: %s\n%s\n", sig.ToString(), sigHolder.ToString());
                fAllSigsValid = false;
                break;
            }

            if (sig.hashPrevBlock != pblock->hashPrevBlock) {
                LogPrintf("Invalid signature found for wrong tip. Trying next set.\n%s\n", sig.ToString());
                fAllSigsValid = false;
                break;
            }

            if (sig.nCreatorId != pblock->nCreatorId) {
                LogPrintf("Invalid signature found for wrong creator ID. Trying next set.\n%s\n", sig.ToString());
                fAllSigsValid = false;
                break;
            }

            sigs[count++] = (uint8_t *)&sig.signature.begin()[0];
        }

        if (!fAllSigsValid)
            continue;

        LogPrint("cvnsig", "all %d partial chain signatures in set found valid.\n", setSigners.size());

        CSchnorrSig allsig;
        int ret = CombinePartialSignatures(allsig, sigs, count);
        if (ret != 1) {
            LogPrintf("could not combine schnorr signatures: %d", ret);
            continue;
        }

        vector<uint32_t> vMissingSignerIds;
        BOOST_FOREACH(const CvnMapType::value_type &i, mapCVNs) {
            if (setSigners.find(i.first) == setSigners.end()) {
                vMissingSignerIds.push_back(i.first);
                LogPrintf("adding 0x%08x to the list of missing nodes\n", i.first);
            }
        }

        sigCandidates.push_back(allsig);
        vMissingSignerIdsCandidates.push_back(vMissingSignerIds);
    }

    /*
     * Try to find the best of the working set, meaning the one with the least missing signatures
     */

    if (vMissingSignerIdsCandidates.empty()) {
        LogPrintf("no working signature set found out of %d. Cannot create block.\nPrinting Signature tree:\n%s\n", sigHolder.sigs.size(), sigHolder.ToString());
        return false;
    }

    // if there's only one set, take that
    if (vMissingSignerIdsCandidates.size() == 1) {
        pblock->vMissingSignerIds = vMissingSignerIdsCandidates[0];
        pblock->chainMultiSig     = sigCandidates[0];
        return true;
    }

    size_t nLeastMissing = MAX_NUMBER_OF_CVNS;
    int nIndex = 0;
    vector<uint32_t> vLeastMissing;
    CSchnorrSig bestChainMultiSig;

    BOOST_FOREACH(const MissingIdsCandidates::value_type &m, vMissingSignerIdsCandidates) {
        if (m.size() < nLeastMissing) {
            nLeastMissing = m.size();
            vLeastMissing = m;
            bestChainMultiSig = sigCandidates[nIndex];
        }

        nIndex++;
    }

    if (bestChainMultiSig.IsNull()) {
        LogPrintf("could not determine chain signature of best set. Cannot create block.\nIndex: %d\nDumping signature tree:\n%s\n", nIndex, sigHolder.ToString());
        return false;
    }

    pblock->vMissingSignerIds = vLeastMissing;
    pblock->chainMultiSig     = bestChainMultiSig;

    return true;
}

static bool CreateNewBlock(CBlockTemplate& blockTemplate)
{
    PopulateBlock(blockTemplate);
    CBlock *pblock = &blockTemplate.block;

    pblock->nCreatorId = blockTemplate.nNodeId;
    pblock->nTime = blockTemplate.nCurrentTime;

    uint256 hashBlock = pblock->hashPrevBlock;
    if (mapCVNs.size() == 1) {
        /* if we only have one CVN available (e.g. during bootstrap) we use a plain Schnorr signature */
        LOCK(sigHolder.cs_sigHolder);
        const MapSigCommonR &commonR = sigHolder.sigs;

        if (!commonR.empty() && !commonR.begin()->second.empty()) {
            const MapSigSigner &mapSigner = commonR.begin()->second;
            if (!mapSigner.empty()) {
                const CCvnPartialSignature &singleSig = mapSigner.begin()->second;
                pblock->chainMultiSig = singleSig.signature;
            }
        }

        if (pblock->chainMultiSig.IsNull()) {
            LogPrintf("CreateNewBlock : cannot create block. Single signature not available\n");
            return false;
        }
    } else {
        if (!DetermineBestSignatureSet(blockTemplate.pindexPrev, pblock))
            return false;
    }

    {
        LOCK(cs_mapChainData);
        if (mapChainData.count(hashBlock)) {
            CChainDataMsg& msg = mapChainData[hashBlock];
            if (!AddChainDataToBlock(pblock, msg)) {
                LogPrintf("CreateNewBlock : could not add chain data to block\n");
            }
        }
    }

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    pblock->hashPayload    = pblock->GetPayloadHash();

    if (!CvnSignBlock(*pblock)) {
        LogPrintf("CreateNewBlock : could not sign block %s\n", pblock->GetHash().ToString());
        return false;
    }

    uint32_t nSigsBlock = mapCVNs.size() - pblock->vMissingSignerIds.size();
    LogPrintf("creating new block with %u transactions, %u CvnInfo, %u signatures, %u bytes\n",
            pblock->vtx.size(), pblock->vCvns.size(),
            nSigsBlock,
            ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

    // final tests
    CValidationState state;
    if (!TestBlockValidity(state, blockTemplate.chainparams, *pblock, blockTemplate.pindexPrev)) {
        LogPrintf("CreateNewBlock : TestBlockValidity failed: %s\n", FormatStateMessage(state));
        return false;
    }

    if (!ProcessRewardBlock(pblock, blockTemplate.chainparams)) {
        LogPrintf("CreateNewBlock : block not accepted, invalid server address");
        return false;
    }
    
    if (!ProcessCVNBlock(pblock, blockTemplate.chainparams)) {
        LogPrintf("CreateNewBlock : block not accepted %s\n", pblock->GetHash().ToString());
        return false;
    }

    return true;
}

bool CreateBlock(const POCStateHolder& s)
{
    CBlockTemplate blockTemplate(s.feeScript, chainActive.Tip(), s.nNodeId, GetAdjustedTime(), (rand() % 1000000 + 1), s.chainparams);

    if (!CreateNewBlock(blockTemplate))
        return false;

    return true;
}
