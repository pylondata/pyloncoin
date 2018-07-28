// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>

#include "primitives/block.h"

#include "hash.h"
#include "util.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "pubkey.h"
#include "consensus/params.h"
#include "poc.h"

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlock::GetPayloadHash(const bool fAdminDataOnly) const
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashPrevBlock;

    if (!fAdminDataOnly) {
        hasher << vMissingSignerIds << chainMultiSig;
        if (HasAdminPayload())
            hasher << vAdminIds << adminMultiSig;
    }

    if (HasCvnInfo())
        hasher << vCvns;
    if (HasChainParameters())
        hasher << dynamicChainParams;
    if (HasChainAdmins())
        hasher << vChainAdmins;
    if (HasCoinSupplyPayload())
        hasher << coinSupply;
    return hasher.GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s, payload;

    if (HasTx())
        payload << "tx";
    if (HasCvnInfo())
        payload << strprintf("%scvninfo", (payload.tellp() > 0) ? "|" : "");
    if (HasChainParameters())
        payload << strprintf("%sparams", (payload.tellp() > 0) ? "|" : "");
    if (HasChainAdmins())
        payload << strprintf("%sadmins", (payload.tellp() > 0) ? "|" : "");
    if (HasCoinSupplyPayload())
        payload << strprintf("%ssupply", (payload.tellp() > 0) ? "|" : "");

    s << strprintf("CBlock(hash=%s, ver=%d, payload=%s, hashPrevBlock=%s, hashMerkleRoot=%s, hashPayload=%s, nTime=%u, nCreatorId=0x%08x, vtx=%u, missing=%u)\n",
        GetHash().ToString(),
        nVersion & 0xff, payload.str(),
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        hashPayload.ToString(),
        nTime, nCreatorId,
		vtx.size(), vMissingSignerIds.size());
    if (HasAdminPayload())
    	s << strprintf("  AdminSignature(%u): %s\n", vAdminIds.size(), adminMultiSig.ToString());
    s << strprintf("  ChainSignature(%u): %s\n", GetNumChainSigs(this), chainMultiSig.ToString());
    s << "  CreatorSignature: " << creatorSignature.ToString() << "\n";

    if (HasCvnInfo())
    {
        for (unsigned int i = 0; i < vCvns.size(); i++)
        {
            s << "  " << vCvns[i].ToString() << "\n";
        }
    }
    if (HasChainParameters())
    {
        s << "  " << dynamicChainParams.ToString() << "\n";
    }
    if (HasCoinSupplyPayload())
    {
        s << "  " << coinSupply.ToString() << "\n";
    }
    if (HasChainAdmins())
    {
        for (unsigned int i = 0; i < vChainAdmins.size(); i++)
        {
            s << "  " << vChainAdmins[i].ToString() << "\n";
        }
    }
    if (HasTx())
    {
        for (unsigned int i = 0; i < vtx.size(); i++)
        {
            s << "  " << vtx[i]->ToString() << "\n";
        }
    }
    return s.str();
}

int64_t GetBlockWeight(const CBlock& block)
{
    // This implements the weight = (stripped_size * 4) + witness_size formula,
    // using only serialization with and without witness data. As witness_size
    // is equal to total_size - stripped_size, this formula is identical to:
    // weight = (stripped_size * 3) + total_size.
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}