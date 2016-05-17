// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/cvn.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

uint256 CDynamicChainParams::GetHash() const
{
    return SerializeHash(*this);
}

std::string CDynamicChainParams::ToString() const
{
    std::stringstream s;
        s << strprintf("CDynamicChainParams(ver=%d, minCvnSigners=%u, maxCvnSigners=%u, blockSpacing=%u, blockSpacingGracePeriod=%u, dustThreshold=%u, minSuccessiveSignatures=%u)",
            nVersion,
            nMinCvnSigners, nMaxCvnSigners,
            nBlockSpacing, nBlockSpacingGracePeriod,
            nDustThreshold,
            nMinSuccessiveSignatures
        );
    return s.str();
}

uint256 CCvnSignatureMsg::GetHash() const
{
    return SerializeHash(*this);
}

std::string CCvnSignature::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnSignature(signerId=0x%08x, ver=%d, sig=%s)",
        nSignerId,
        nVersion,
        HexStr(vSignature)); //TODO: limit again .substr(0, 30));
    return s.str();
}

std::string CCvnInfo::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnInfo(nodeId=0x%08x, heightAdded=%u, pubkey=%s)",
        nNodeId, nHeightAdded,
        HexStr(vPubKey));
    return s.str();
}

std::string CChainAdmin::ToString() const
{
    std::stringstream s;
    s << strprintf("CChainAdmin(adminId=0x%08x, pubkey=%s)",
        nAdminId,
        HexStr(vPubKey));
    return s.str();
}

uint256 CChainDataMsg::HashChainAdmins() const
{
    return SerializeHash(this->vChainAdmins);
}

uint256 CChainDataMsg::HashCVNs() const
{
    return SerializeHash(this->vCvns);
}

uint256 CChainDataMsg::GetHash() const
{
    std::vector<uint256> hashes;

    hashes.push_back(hashPrevBlock);

    if (HasCvnInfo())
        hashes.push_back(HashCVNs());
    if (HasChainAdmins())
        hashes.push_back(HashChainAdmins());
    if (HasChainParameters())
        hashes.push_back(dynamicChainParams.GetHash());

    return Hash(hashes.begin(), hashes.end());
}

std::string CChainDataMsg::ToString() const
{
    std::stringstream s, payload;

    if (HasCvnInfo())
        payload << strprintf("%scvninfo", (payload.tellp() > 0) ? "," : "");
    if (HasChainAdmins())
        payload << strprintf("%sadmins", (payload.tellp() > 0) ? "," : "");
    if (HasChainParameters())
        payload << strprintf("%sparams", (payload.tellp() > 0) ? "," : "");

    s << strprintf("CChainDataMsg(payload(%u)=%s, hashPrevBlock=%s, signers=%u)",
        nPayload, payload.str(),
        hashPrevBlock.ToString(),
        vAdminSignatures.size()); //TODO: add more

    return s.str();
}
