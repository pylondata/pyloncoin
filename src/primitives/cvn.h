// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_CVN_H
#define BITCOIN_PRIMITIVES_CVN_H

#include "serialize.h"
#include "uint256.h"

using namespace std;

/** CVNs send this signature to the creator of the next block
 * to proof consensus about the block.
 */
class CCvnSignature
{
public:
    static const int32_t CURRENT_VERSION=1;
    int32_t nVersion;
    uint32_t nSignerId;
    vector<unsigned char> vSignature;

    CCvnSignature()
    {
        SetNull();
    }

    CCvnSignature(const uint32_t nSignerNodeId, const int32_t nVersion = CCvnSignature::CURRENT_VERSION)
    {
        this->nVersion = nVersion;
        this->nSignerId = nSignerNodeId;
        this->vSignature.clear();
    }

    CCvnSignature(const uint32_t nSignerNodeId, vector<unsigned char> vSignature, const int32_t nVersion = CCvnSignature::CURRENT_VERSION)
    {
        this->nVersion = nVersion;
        this->nSignerId = nSignerNodeId;
        this->vSignature = vSignature;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nSignerId);
        READWRITE(vSignature);
    }

    void SetNull()
    {
        nVersion = CCvnSignature::CURRENT_VERSION;
        nSignerId = 0;
        vSignature.clear();
    }

    string ToString() const;
};

class CCvnSignatureMsg : public CCvnSignature
{
public:
    uint256 hashPrev;
    uint32_t nCreatorId; // the CVN node ID of the creator of the next block

    CCvnSignatureMsg()
    {
        SetNull();
    }

    void SetNull()
    {
        CCvnSignature::SetNull();
        hashPrev.SetNull();
        nCreatorId = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CCvnSignature*)this);
        READWRITE(hashPrev);
        READWRITE(nCreatorId);
    }

    CCvnSignature GetCvnSignature() const
    {
        CCvnSignature msg;
        msg.nVersion   = nVersion;
        msg.nSignerId  = nSignerId;
        msg.vSignature = vSignature;
        return msg;
    }

    uint256 GetHash() const;
};

class CCvnInfo
{
public:

    uint32_t nNodeId;
    uint32_t nHeightAdded;
    vector<unsigned char> vPubKey;

    CCvnInfo()
    {
        SetNull();
    }

    CCvnInfo(const uint32_t nNodeId, const uint32_t nHeightAdded, const vector<unsigned char> vPubKey)
    {
        this->nNodeId = nNodeId;
        this->nHeightAdded = nHeightAdded;
        this->vPubKey = vPubKey;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nNodeId);
        READWRITE(nHeightAdded);
        READWRITE(vPubKey);
    }

    void SetNull()
    {
        nNodeId = 0;
        nHeightAdded = 0;
        vPubKey.clear();
    }

    string ToString() const;
};

class CChainAdmin
{
public:

    uint32_t nAdminId;
    vector<unsigned char> vPubKey;

    CChainAdmin()
    {
        SetNull();
    }

    CChainAdmin(const uint32_t nAdminId, const vector<unsigned char> vPubKey)
    {
        this->nAdminId = nAdminId;
        this->vPubKey = vPubKey;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nAdminId);
        READWRITE(vPubKey);
    }

    void SetNull()
    {
        nAdminId = 0;
        vPubKey.clear();
    }

    uint256 GetHash() const;

    string ToString() const;
};

class CDynamicChainParams
{
public:
    static const uint32_t CURRENT_VERSION = 1;
    uint32_t nVersion;
    uint32_t nMinCvnSigners;
    uint32_t nMaxCvnSigners;
    uint32_t nBlockSpacing; // in seconds
    uint32_t nBlockSpacingGracePeriod; // in seconds
    uint32_t nDustThreshold; // in µFAIR
    // for a node to create the next block it needs to have co-signed
    // the last nMinSuccessiveSignatures blocks
    uint32_t nMinSuccessiveSignatures;

    CDynamicChainParams()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nMinCvnSigners);
        READWRITE(nMaxCvnSigners);
        READWRITE(nBlockSpacing);
        READWRITE(nBlockSpacingGracePeriod);
        READWRITE(nDustThreshold);
        READWRITE(nMinSuccessiveSignatures);
    }

    void SetNull()
    {
        nVersion = CDynamicChainParams::CURRENT_VERSION;
        nMaxCvnSigners = 0;
        nMinCvnSigners = 0;
        nBlockSpacing = 0;
        nBlockSpacingGracePeriod = 0;
        nDustThreshold = 0;
        nMinSuccessiveSignatures = 0;
    }

    uint256 GetHash() const;

    string ToString() const;
};

// PoC chain data messages can have different payload types
class CChainDataMsg
{
public:
    static const int32_t              CVN_PAYLOAD = 1 << 0;
    static const int32_t     CHAIN_ADMINS_PAYLOAD = 1 << 1;
    static const int32_t CHAIN_PARAMETERS_PAYLOAD = 1 << 2;
    uint32_t nPayload;

    // this chain data must be contained in the block after this hash
    uint256 hashPrevBlock;

    vector<CCvnInfo> vCvns;
    vector<CChainAdmin> vChainAdmins;
    CDynamicChainParams dynamicChainParams;

    // these are the administrator signatures of the payload hash
    vector<CCvnSignature> vAdminSignatures;

    CChainDataMsg()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nPayload);
        READWRITE(hashPrevBlock);
        READWRITE(vAdminSignatures);

        if (HasCvnInfo())
            READWRITE(vCvns);
        if (HasChainAdmins())
            READWRITE(vChainAdmins);
        if (HasChainParameters())
            READWRITE(dynamicChainParams);
    }

    void SetNull()
    {
        nPayload = 0;
        hashPrevBlock.SetNull();
        vAdminSignatures.clear();
        vCvns.clear();
        vChainAdmins.clear();
        dynamicChainParams.SetNull();
    }

    uint256 HashChainAdmins() const;

    uint256 HashCVNs() const;

    // this is the payload hash the chain administrators have to sign
    uint256 GetHash() const;

    string ToString() const;

    bool HasCvnInfo() const
    {
        return (nPayload & CVN_PAYLOAD);
    }

    bool HasChainAdmins() const
    {
        return (nPayload & CHAIN_ADMINS_PAYLOAD);
    }

    bool HasChainParameters() const
    {
        return (nPayload & CHAIN_PARAMETERS_PAYLOAD);
    }
};

#endif // BITCOIN_PRIMITIVES_CVN_H
