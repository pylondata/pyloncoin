// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "primitives/block.h"
#include "key.h"
#include "chainparams.h"

#include <stdint.h>

class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;
class POCStateHolder;

namespace Consensus { struct Params; };

static const bool DEFAULT_GENERATE = false;

static const bool DEFAULT_PRINTPRIORITY = false;

extern bool CreateBlock(const POCStateHolder& s);
extern bool DetermineBestSignatureSet(CBlockIndex * const pindexPrev, CBlock *pblock);

class CBlockTemplate
{
public:
    CBlock block;
    CReserveScript& feeScript;
    CBlockIndex* pindexPrev;
    uint32_t nNodeId;
    uint32_t nCurrentTime;
    uint32_t nExtraNonce;
    const CChainParams& chainparams;

    CBlockTemplate(CReserveScript& feeScript, CBlockIndex* pindexPrev, uint32_t nNodeId, uint32_t nCurrentTime, uint32_t nExtraNonce, const CChainParams& chainparams)
    : feeScript(feeScript), chainparams(chainparams)
    {
        this->pindexPrev = pindexPrev;
        this->nCurrentTime = nCurrentTime;
        this->nExtraNonce  = nExtraNonce;
        this->nNodeId      = nNodeId;
    }
};

#endif // BITCOIN_MINER_H
