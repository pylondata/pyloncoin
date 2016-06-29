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
namespace Consensus { struct Params; };

static const bool DEFAULT_GENERATE = false;

static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
	CReserveScript* coinbaseScript;
	CBlockIndex* pindexPrev;
	uint32_t nNodeId;
	uint32_t nCurrentTime;
	uint32_t nExtraNonce;
};

/** Run the CVN thread */
void RunCertifiedValidationNode(const bool fGenerate, const CChainParams& chainparams, const uint32_t& nNodeId);

#endif // BITCOIN_MINER_H
