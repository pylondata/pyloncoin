// Copyright (c) 2016-2017 The Pyloncoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <string.h>

#include <boost/foreach.hpp>

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
                       "transactionFee=%u, dustThreshold=%u, minSuccessiveSignatures=%u, nBlocksToConsiderForSigCheck=%u, nPercentageOfSignaturesMean=%u, nMaxBlockSize=%u, "
                       "blockPropagationWaitTime=%u, retryNewSigSetInterval=%u, nCoinbaseMaturity=%u, description='%s')",
            nVersion,
            nMinAdminSigs, nMaxAdminSigs,
            nBlockSpacing, nBlockSpacingGracePeriod,
            nTransactionFee, nDustThreshold,
            nMinSuccessiveSignatures, nBlocksToConsiderForSigCheck,
            nPercentageOfSignaturesMean, nMaxBlockSize,
            nBlockPropagationWaitTime, nRetryNewSigSetInterval,
            nCoinbaseMaturity, strDescription
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
        s << strprintf("CCoinSupply(ver=%d, nValue=%d.%08d, isFinal=%s, description='%s', rawScriptDestination=%s, asm=%s)",
            nVersion,
            nValue / COIN, nValue % COIN,
            fFinalCoinsSupply ? "true" : "false",
            strDescription,
            HexStr(scriptDestination),
            ScriptToAsmStr(scriptDestination)
        );
    return s.str();
}

uint256 CAdminNonceUnsigned::GetHash() const
{
    return SerializeHash(*this);
}

std::string CAdminNonceUnsigned::ToString() const
{
    std::stringstream s;
    s << strprintf("CAdminNonceUnsigned(adminId=0x%08x, hashRoot=%s, creationTime=%u, nonce=%s)",
        nAdminId, hashRootBlock.ToString(), nCreationTime, publicNonce.ToString());
    return s.str();
}

uint256 CAdminPartialSignatureUnsinged::GetHash() const
{
    return SerializeHash(*this);
}

std::string CAdminPartialSignatureUnsinged::ToString() const
{
    std::stringstream s;
    s << strprintf("CAdminPartialSignatureUnsinged(adminId=0x%08x, hashRoot=%s, sig=%s, signers=%s)",
        nAdminId, hashRootBlock.ToString(),
        signature.ToString(), vSignerIds.size());
    return s.str();
}

uint256 CCvnPartialSignatureUnsinged::GetHash() const
{
    return SerializeHash(*this);
}

std::string CCvnPartialSignatureUnsinged::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnPartialSignatureUnsinged(signerId=0x%08x, nextCreatorId=0x%08x, hashPrev=%s, ver=%d, sig=%s, missing=%d)",
        nSignerId, nCreatorId, hashPrevBlock.ToString(), nVersion,
        signature.ToString(), vMissingSignerIds.size());
    return s.str();
}

std::string CCvnPartialSignature::ToString() const
{
    std::stringstream s;
    s << strprintf("%s :: msgSig=%s)",
        CCvnPartialSignatureUnsinged::ToString(), msgSig.ToString());
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
        hasher << vCvns;
    if (HasChainParameters())
        hasher << dynamicChainParams;
    if (HasChainAdmins())
        hasher << vChainAdmins;
    if (HasCoinSupplyPayload())
        hasher << coinSupply;
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

uint256 CNoncePoolUnsigned::GetHash() const
{
    return SerializeHash(*this);
}

std::string CNoncePoolUnsigned::ToString(const bool fVerbose) const
{
    std::stringstream s;

    s << strprintf("CNoncePoolUnsigned(cvnID=0x%08x, size=%u, rootHash=%s, createionTime=%u)\n",
            nCvnId, vPublicNonces.size(), hashRootBlock.ToString(), nCreationTime);

    if (fVerbose) {
        BOOST_FOREACH(const CSchnorrNonce &nonce, vPublicNonces) {
            s << "  " << nonce.ToString() << "\n";
        }
        s << "\n";
    }

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
    vector<unsigned char> vchHex = ParseHex(&str[2]); // skip the first 0x04
    reverse_copy(vchHex.begin(), vchHex.begin() + WIDTH / 2, data);
    reverse_copy(vchHex.begin() + WIDTH / 2, vchHex.end(), &data[WIDTH / 2]);
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
