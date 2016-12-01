// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_CVN_H
#define BITCOIN_PRIMITIVES_CVN_H

#include "serialize.h"
#include "uint256.h"
#include "script/script.h"
#include "amount.h"
#include "hash.h"

using namespace std;

template <unsigned int BYTES>
class poc_storage
{
protected:
    enum { WIDTH = BYTES };
    uint8_t data[WIDTH];
public:
    poc_storage()
    {
        SetNull();
    }

    explicit poc_storage(const std::vector<unsigned char>& vch);

    poc_storage(const unsigned char *pch)
    {
        memcpy(data, pch, WIDTH);
    }

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(data, 0, WIDTH);
    }

    friend inline bool operator==(const poc_storage& a, const poc_storage& b) { return memcmp(a.data, b.data, sizeof(a.data)) == 0; }
    friend inline bool operator!=(const poc_storage& a, const poc_storage& b) { return memcmp(a.data, b.data, sizeof(a.data)) != 0; }
    friend inline bool operator<(const poc_storage& a, const poc_storage& b) { return memcmp(a.data, b.data, sizeof(a.data)) < 0; }

    std::string GetHex() const;
    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    void SetHexDER(const std::string& str);
    std::string ToString() const;

    unsigned char* begin()
    {
        return &data[0];
    }

    unsigned char* end()
    {
        return &data[WIDTH];
    }

    const unsigned char* begin() const
    {
        return &data[0];
    }

    const unsigned char* end() const
    {
        return &data[WIDTH];
    }

    unsigned int size() const
    {
        return sizeof(data);
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return sizeof(data);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        s.write((char*)data, WIDTH);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        s.read((char*)data, WIDTH);
    }
};

class CSchnorrSig : public poc_storage<64> {
public:
    CSchnorrSig() {}
    CSchnorrSig(const poc_storage<64>& b) : poc_storage<64>(b) {}
    explicit CSchnorrSig(const std::vector<unsigned char>& vch) : poc_storage<64>(vch) {}
};

class CSchnorrNonce : public poc_storage<64> {
public:
    CSchnorrNonce() {}
    CSchnorrNonce(const poc_storage<64>& b) : poc_storage<64>(b) {}
    explicit CSchnorrNonce(const std::vector<unsigned char>& vch) : poc_storage<64>(vch) {}
};

inline CSchnorrSig CSchnorrSigS(const std::string& str)
{
    CSchnorrSig rv;
    rv.SetHex(str);
    return rv;
}

class CSchnorrPubKey : public poc_storage<64> {
public:
    CSchnorrPubKey() {}
    CSchnorrPubKey(const poc_storage<64>& b) : poc_storage<64>(b) {}
    CSchnorrPubKey(const unsigned char *pch) : poc_storage<64>(pch) {}
    explicit CSchnorrPubKey(const std::vector<unsigned char>& vch) : poc_storage<64>(vch) {}
    uint160 GetHash160() const
    {
        vector<unsigned char> vData;
        vData.insert(vData.begin(), 0x04);
        vData.insert(vData.begin(), data, data + WIDTH); // TODO: reverse data and &data[32]
        return Hash160(vData);
    }
};

inline CSchnorrPubKey CSchnorrPubKeyS(const std::string& str)
{
    CSchnorrPubKey rv;
    if (str.length() != 64 * 2)
           return NULL;
    rv.SetHex(str);
    return rv;
}

inline CSchnorrPubKey CSchnorrPubKeyDER(const std::string& str)
{
    CSchnorrPubKey rv;

    if (str.length() != 65 * 2 || (str[0] != '0' && str[1] != '4'))
        return NULL;
    rv.SetHexDER(str);
    return rv;
}

/* only used for test network (-cvn=file)
 * and type safety */
class CSchnorrPrivNonce : public poc_storage<32> {
public:
    CSchnorrPrivNonce() {}
    CSchnorrPrivNonce(const poc_storage<32>& b) : poc_storage<32>(b) {}
    explicit CSchnorrPrivNonce(const std::vector<unsigned char>& vch) : poc_storage<32>(vch) {}
};

class CCvnPubNonce
{
public:
    static const int32_t CURRENT_VERSION = 1;
    int32_t nVersion;
    uint32_t nSignerId;
    CSchnorrNonce pubNonce;

    CCvnPubNonce()
    {
        SetNull();
    }

    CCvnPubNonce(const uint32_t nSignerId, const int32_t nVersion = CCvnPubNonce::CURRENT_VERSION)
    {
        this->nVersion  = nVersion;
        this->nSignerId = nSignerId;
        this->pubNonce.SetNull();
    }

    CCvnPubNonce(const uint32_t nSignerId, const CSchnorrNonce& pubNonce, const int32_t nVersion = CCvnPubNonce::CURRENT_VERSION)
    {
        this->nVersion  = nVersion;
        this->nSignerId = nSignerId;
        this->pubNonce  = pubNonce;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nSignerId);
        READWRITE(pubNonce);
    }

    void SetNull()
    {
        nVersion = CCvnPubNonce::CURRENT_VERSION;
        nSignerId = 0;
        this->pubNonce.SetNull();
    }

    string ToString() const;
};

class CCvnPubNonceMsg : public CCvnPubNonce
{
public:
    uint256 hashPrevBlock;
    uint32_t nCreatorId; // the CVN ID of the creator of the next block
    CSchnorrSig msgSig;

    CCvnPubNonceMsg()
    {
        SetNull();
    }

    CCvnPubNonceMsg(const CCvnPubNonce nonce, const uint256 hashPrevBlock, const uint32_t nCreatorId)
        : CCvnPubNonce(nonce.nSignerId, nonce.pubNonce, nonce.nVersion)
    {
        this->hashPrevBlock = hashPrevBlock;
        this->nCreatorId    = nCreatorId;
        this->msgSig.SetNull();
    }

    void SetNull()
    {
        CCvnPubNonce::SetNull();
        hashPrevBlock.SetNull();
        nCreatorId = 0;
        this->msgSig.SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CCvnPubNonce*)this);
        READWRITE(hashPrevBlock);
        READWRITE(nCreatorId);
        READWRITE(msgSig);
    }

    CCvnPubNonce GetPubNonce() const
    {
        CCvnPubNonce nonce(nSignerId, pubNonce, nVersion);
        return nonce;
    }

    uint256 GetHash() const;

    string ToString() const;
};


/** CVNs send this signature to the creator of the next block
 * to proof consensus about the block.
 */
class CCvnPartialSignature
{
public:
    static const int32_t CURRENT_VERSION=1;
    int32_t nVersion;
    uint32_t nSignerId;
    CSchnorrSig signature;
    vector<uint32_t> vMissingPubNonces; // contains the CVN IDs of those that we didn't receive pubnonces from

    CCvnPartialSignature()
    {
        SetNull();
    }

    CCvnPartialSignature(const uint32_t nSignerId, const vector<uint32_t> vMissingPubNonces, const int32_t nVersion = CCvnPartialSignature::CURRENT_VERSION)
    {
        this->nVersion          = nVersion;
        this->nSignerId         = nSignerId;
        this->signature.SetNull();
        this->vMissingPubNonces = vMissingPubNonces;
    }

    CCvnPartialSignature(const uint32_t nSignerId, const vector<uint32_t> vMissingPubNonces, const CSchnorrSig& signature, const int32_t nVersion = CCvnPartialSignature::CURRENT_VERSION)
    {
        this->nVersion          = nVersion;
        this->nSignerId         = nSignerId;
        this->signature         = signature;
        this->vMissingPubNonces = vMissingPubNonces;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nSignerId);
        READWRITE(signature);
        READWRITE(vMissingPubNonces);
    }

    void SetNull()
    {
        nVersion = CCvnPartialSignature::CURRENT_VERSION;
        nSignerId = 0;
        signature.SetNull();
        vMissingPubNonces.clear();
    }

    string ToString() const;
};

class CCvnPartialSignatureMsg : public CCvnPartialSignature
{
public:
    uint256 hashPrevBlock;
    uint32_t nCreatorId; // the CVN node ID of the creator of the next block
    CSchnorrSig msgSig;

    CCvnPartialSignatureMsg()
    {
        SetNull();
    }

    CCvnPartialSignatureMsg(const CCvnPartialSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId)
        : CCvnPartialSignature(signature.nSignerId, signature.vMissingPubNonces, signature.signature, signature.nVersion)
    {
        this->hashPrevBlock = hashPrevBlock;
        this->nCreatorId    = nCreatorId;
        this->msgSig.SetNull();
    }

    void SetNull()
    {
        CCvnPartialSignature::SetNull();
        hashPrevBlock.SetNull();
        nCreatorId = 0;
        this->msgSig.SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CCvnPartialSignature*)this);
        READWRITE(hashPrevBlock);
        READWRITE(nCreatorId);
        READWRITE(msgSig);
    }

    CCvnPartialSignature GetCvnSignature() const
    {
        CCvnPartialSignature sig(nSignerId, vMissingPubNonces, signature, nVersion);
        return sig;
    }

    uint256 GetHash() const;

    string ToString() const;
};

class CCvnInfo
{
public:

    uint32_t nNodeId;
    uint32_t nHeightAdded;
    CSchnorrPubKey pubKey;

    CCvnInfo()
    {
        SetNull();
    }

    CCvnInfo(const uint32_t nNodeId, const uint32_t nHeightAdded, const CSchnorrPubKey& pubKey)
    {
        this->nNodeId      = nNodeId;
        this->nHeightAdded = nHeightAdded;
        this->pubKey       = pubKey;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nNodeId);
        READWRITE(nHeightAdded);
        READWRITE(pubKey);
    }

    void SetNull()
    {
        nNodeId = 0;
        nHeightAdded = 0;
        pubKey.SetNull();
    }

    string ToString() const;
};

class CChainAdmin
{
public:

    uint32_t nAdminId;
    uint32_t nHeightAdded;
    CSchnorrPubKey pubKey;

    CChainAdmin()
    {
        SetNull();
    }

    CChainAdmin(const uint32_t nAdminId, const uint32_t nHeightAdded, const CSchnorrPubKey& pubKey)
    {
        this->nAdminId     = nAdminId;
        this->nHeightAdded = nHeightAdded;
        this->pubKey       = pubKey;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nAdminId);
        READWRITE(nHeightAdded);
        READWRITE(pubKey);
    }

    void SetNull()
    {
        nAdminId = 0;
        nHeightAdded = 0;
        pubKey.SetNull();
    }

    uint256 GetHash() const;

    string ToString() const;
};

class CDynamicChainParams
{
public:
    static const uint32_t CURRENT_VERSION = 1;
    uint32_t nVersion;

    /** chain admin signatures */
    uint32_t nMinAdminSigs;
    uint32_t nMaxAdminSigs;

    uint32_t nBlockSpacing; // in seconds
    uint32_t nBlockSpacingGracePeriod; // in seconds

    CAmount nTransactionFee; // in µFAIR
    CAmount nDustThreshold; // in µFAIR

    /** for a node to create the next block it needs to have co-signed */
    /** the last nMinSuccessiveSignatures blocks */
    uint32_t nMinSuccessiveSignatures;

    /** The number of blocks to consider for calculation of the mean number of signature */
    uint32_t nBlocksToConsiderForSigCheck;

    /** minimum percentage of the number of nSignatureMean that are required to create the next block */
    uint32_t nPercentageOfSignaturesMean;

    /** The maximum allowed size for a serialized block */
    uint32_t nMaxBlockSize;

    CDynamicChainParams()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nMinAdminSigs);
        READWRITE(nMaxAdminSigs);
        READWRITE(nBlockSpacing);
        READWRITE(nBlockSpacingGracePeriod);
        READWRITE(nTransactionFee);
        READWRITE(nDustThreshold);
        READWRITE(nMinSuccessiveSignatures);
        READWRITE(nBlocksToConsiderForSigCheck);
        READWRITE(nPercentageOfSignaturesMean);
        READWRITE(nMaxBlockSize);
    }

    void SetNull()
    {
        nVersion = CDynamicChainParams::CURRENT_VERSION;
        nMaxAdminSigs = 0;
        nMinAdminSigs = 0;
        nBlockSpacing = 0;
        nBlockSpacingGracePeriod = 0;
        nTransactionFee = 0;
        nDustThreshold = 0;
        nMinSuccessiveSignatures = 0;
        nBlocksToConsiderForSigCheck = 0;
        nPercentageOfSignaturesMean = 0;
        nMaxBlockSize = 0;
    }

    uint256 GetHash() const;

    string ToString() const;
};

class CCoinSupply
{
public:
    static const uint32_t CURRENT_VERSION = 1;
    uint32_t nVersion;
    CAmount nValue;
    CScript scriptDestination;

    CCoinSupply()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptDestination));
    }

    void SetNull()
    {
        nVersion = CDynamicChainParams::CURRENT_VERSION;
        nValue = -1;
        scriptDestination.clear();
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
    static const int32_t      COIN_SUPPLY_PAYLOAD = 1 << 3;
    uint32_t nPayload;

    // this chain data must be contained in the block after this hash
    uint256 hashPrevBlock;

    vector<CCvnInfo> vCvns;
    vector<CChainAdmin> vChainAdmins;
    CDynamicChainParams dynamicChainParams;

    // this is the multi sig of the chain administrators of the payload hash
    CSchnorrSig adminMultiSig;
    vector<uint32_t> vAdminIds;

    CCoinSupply coinSupply;
    string strComment; // currently only used with coinSupply

    CChainDataMsg()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nPayload);
        READWRITE(hashPrevBlock);
        READWRITE(adminMultiSig);
        READWRITE(vAdminIds);

        if (HasCvnInfo())
            READWRITE(vCvns);
        if (HasChainAdmins())
            READWRITE(vChainAdmins);
        if (HasChainParameters())
            READWRITE(dynamicChainParams);
        if (HasCoinSupplyPayload()) {
            READWRITE(coinSupply);
            READWRITE(strComment);
        }
    }

    void SetNull()
    {
        nPayload = 0;
        hashPrevBlock.SetNull();
        adminMultiSig.SetNull();
        vAdminIds.clear();
        vCvns.clear();
        vChainAdmins.clear();
        dynamicChainParams.SetNull();
        coinSupply.SetNull();
        strComment.clear();
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

    bool HasCoinSupplyPayload() const
    {
        return (nPayload & COIN_SUPPLY_PAYLOAD);
    }
};

class CCvnStatus
{
public:
    uint32_t nNodeId;
    uint32_t nPredictedNextBlock;
    uint32_t nBlockSigned; // number of blocks signed within the last 'nMinSuccessiveSignatures' blocks

    CCvnStatus()
    {
        SetNull();
    }

    CCvnStatus(const uint32_t nNodeId)
    {
        SetNull();
        this->nNodeId = nNodeId;
    }

    void SetNull()
    {
        nPredictedNextBlock = 0;
        nBlockSigned = 0;
    }
};

#endif // BITCOIN_PRIMITIVES_CVN_H
