// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/cvn.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "base58.h"

uint256 CDynamicChainParams::GetHash() const
{
    return SerializeHash(*this);
}

std::string CDynamicChainParams::ToString() const
{
    std::stringstream s;
        s << strprintf("CDynamicChainParams(ver=%d, minAdminSigs=%u, maxAdminSigs=%u, blockSpacing=%u, blockSpacingGracePeriod=%u, transactionFee=%u, dustThreshold=%u, minSuccessiveSignatures=%u)",
            nVersion,
            nMinAdminSigs, nMaxAdminSigs,
            nBlockSpacing, nBlockSpacingGracePeriod,
            nTransactionFee, nDustThreshold,
            nMinSuccessiveSignatures
        );
    return s.str();
}

uint256 CCoinSupply::GetHash() const
{
    return SerializeHash(*this);
}

std::string CCoinSupply::ToString() const
{
    std::stringstream s;
        s << strprintf("CCoinSupply(ver=%d, nValue=%d.%08d, rawScriptDestination=%s, asm=%s)",
            nVersion,
			nValue / COIN, nValue % COIN,
			HexStr(scriptDestination),
			CBitcoinAddress(CScriptID(scriptDestination)).ToString()
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
    if (HasCoinSupplyPayload())
        hashes.push_back(coinSupply.GetHash());

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
    if (HasCoinSupplyPayload())
        payload << strprintf("%ssupply", (payload.tellp() > 0) ? "," : "");

    s << strprintf("CChainDataMsg(payload(%02x)=%s, hashPrevBlock=%s, signers=%u)",
        nPayload, payload.str(),
        hashPrevBlock.ToString(),
        vAdminSignatures.size()); //TODO: add more

    return s.str();
}
