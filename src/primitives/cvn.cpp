// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <string.h>

#include "primitives/cvn.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "core_io.h"

uint256 CDynamicChainParams::GetHash() const
{
    return SerializeHash(*this);
}

std::string CDynamicChainParams::ToString() const
{
    std::stringstream s;
        s << strprintf("CDynamicChainParams(ver=%d, minAdminSigs=%u, maxAdminSigs=%u, blockSpacing=%u, blockSpacingGracePeriod=%u, "
                       "transactionFee=%u, dustThreshold=%u, minSuccessiveSignatures=%u, nBlocksToConsiderForSigCheck=%u, nPercentageOfSignaturesMean=%u, nMaxBlockSize=%u)",
            nVersion,
            nMinAdminSigs, nMaxAdminSigs,
            nBlockSpacing, nBlockSpacingGracePeriod,
            nTransactionFee, nDustThreshold,
            nMinSuccessiveSignatures, nBlocksToConsiderForSigCheck,
            nPercentageOfSignaturesMean, nMaxBlockSize
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
			ScriptToAsmStr(scriptDestination)
        );
    return s.str();
}

uint256 CCvnPubNonceMsg::GetHash() const
{
    CHashWriter hasher(SER_GETHASH, 0);

    hasher << GetPubNonce() << hashPrevBlock << nCreatorId;

    return hasher.GetHash();
}

std::string CCvnPubNonce::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnPubNonce(signerId=0x%08x, ver=%d, sig=%s)",
        nSignerId,
        nVersion,
        pubNonce.ToString());
    return s.str();
}

std::string CCvnPubNonceMsg::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnPubNonceMsg(creatorId=0x%08x, hashPrev=%s, msgSig=%s) : %s",
        nCreatorId,
        hashPrevBlock.ToString(),
        msgSig.ToString(), CCvnPubNonce::ToString());
    return s.str();
}

uint256 CCvnPartialSignatureMsg::GetHash() const
{
    CHashWriter hasher(SER_GETHASH, 0);

    hasher << GetCvnSignature() << hashPrevBlock << nCreatorId;

    return hasher.GetHash();
}

std::string CCvnPartialSignature::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnSignature(signerId=0x%08x, ver=%d, sig=%s, missing=%d)",
        nSignerId,
        nVersion,
        signature.ToString(), vMissingPubNonces.size()); //TODO: limit again .substr(0, 30));
    return s.str();
}

std::string CCvnPartialSignatureMsg::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnPartialSignatureMsg(creatorId=0x%08x, hashPrev=%s, msgSig=%s) : %s",
        nCreatorId,
        hashPrevBlock.ToString(),
        msgSig.ToString(), CCvnPartialSignature::ToString());
    return s.str();
}

std::string CCvnInfo::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnInfo(nodeId=0x%08x, heightAdded=%u, pubkey=%s)",
        nNodeId, nHeightAdded,
        pubKey.ToString());
    return s.str();
}

std::string CChainAdmin::ToString() const
{
    std::stringstream s;
    s << strprintf("CChainAdmin(adminId=0x%08x, heightAdded=%u, pubkey=%s)",
        nAdminId, nHeightAdded,
        pubKey.ToString());
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
    CHashWriter hasher(SER_GETHASH, 0);

    hasher << hashPrevBlock;

    if (HasCvnInfo())
        hasher << HashCVNs();
    if (HasChainAdmins())
        hasher << HashChainAdmins();
    if (HasChainParameters())
        hasher << dynamicChainParams.GetHash();
    if (HasCoinSupplyPayload())
        hasher << coinSupply.GetHash();

    return hasher.GetHash();
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
        vAdminIds.size()); //TODO: add more

    return s.str();
}

template <unsigned int BYTES>
poc_storage<BYTES>::poc_storage(const std::vector<unsigned char>& vch)
{
    assert(vch.size() == WIDTH);
    memcpy(data, &vch[0], WIDTH);
}

template <unsigned int BYTES>
std::string poc_storage<BYTES>::GetHex() const
{
    char psz[WIDTH * 2 + 1];
    for (unsigned int i = 0; i < sizeof(data); i++)
        sprintf(psz + i * 2, "%02x", data[i]);
    return std::string(psz, psz + WIDTH * 2);
}

template <unsigned int BYTES>
void poc_storage<BYTES>::SetHex(const char* psz)
{
    vector<unsigned char> vchHex = ParseHex(psz);
    memcpy(data, &vchHex.begin()[0], WIDTH);
}

template <unsigned int BYTES>
void poc_storage<BYTES>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BYTES>
std::string poc_storage<BYTES>::ToString() const
{
    return (GetHex());
}

template <unsigned int BYTES>
void poc_storage<BYTES>::SetHexDER(const std::string& str)
{
    vector<unsigned char> vchHex = ParseHex(str);
    reverse(vchHex.begin(), vchHex.end());
    memcpy(data, &vchHex.begin()[WIDTH / 2], WIDTH / 2);
    memcpy(&data[WIDTH / 2], &vchHex.begin()[0], WIDTH / 2);
}

// Explicit instantiations for poc_storage<32>
template poc_storage<32>::poc_storage(const std::vector<unsigned char>&);
template std::string poc_storage<32>::GetHex() const;
template std::string poc_storage<32>::ToString() const;
template void poc_storage<32>::SetHex(const char*);
template void poc_storage<32>::SetHex(const std::string&);

// Explicit instantiations for poc_storage<64>
template poc_storage<64>::poc_storage(const std::vector<unsigned char>&);
template std::string poc_storage<64>::GetHex() const;
template std::string poc_storage<64>::ToString() const;
template void poc_storage<64>::SetHex(const char*);
template void poc_storage<64>::SetHex(const std::string&);
template void poc_storage<64>::SetHexDER(const std::string&);
