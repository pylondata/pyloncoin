// Copyright (c) 2016 The Pyloncoin Core developers
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
    void Serialize(Stream& s) const
    {
        s.write((char*)data, sizeof(data));
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read((char*)data, sizeof(data));
    }
};

class CSchnorrRx : public poc_storage<32> {
public:
    CSchnorrRx() { }
    CSchnorrRx(const poc_storage<32>& b) : poc_storage<32>(b) {}
    explicit CSchnorrRx(const std::vector<unsigned char>& vch) : poc_storage<32>(vch) {}
};

class CSchnorrSig : public poc_storage<64> {
public:
    CSchnorrSig() {}
    CSchnorrSig(const poc_storage<64>& b) : poc_storage<64>(b) {}
    explicit CSchnorrSig(const std::vector<unsigned char>& vch) : poc_storage<64>(vch) {}
    const CSchnorrRx GetRx() const
    {
        return CSchnorrRx(data);
    }
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

    void GetPubKeyDER(vector<unsigned char> &vPubKey) const
    {
        vPubKey.resize(65);
        vPubKey[0] = 0x04;
        reverse_copy(data, data + 32, vPubKey.begin() + 1);
        reverse_copy(&data[32], data + WIDTH, vPubKey.begin() + 33);
    }

    uint160 GetHash160()
    {
        vector<unsigned char> vData;
        GetPubKeyDER(vData);
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
        rv.SetNull();
    else
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

/** CVNs send this signature to the creator of the next block
 * to proof consensus about the block.
 */
class CCvnPartialSignatureUnsinged
{
public:
    static const int32_t CURRENT_VERSION=1;
    int32_t nVersion;
    uint32_t nSignerId;
    uint32_t nCreatorId; // the CVN node ID of the creator of the next block
    uint256 hashPrevBlock;
    CSchnorrSig signature;
    uint32_t nCreationTime;

    bool fValidated; // memory only

    // contains the CVN IDs that did not co-sign (usually all in IDs in mapCVNs should sign)
    vector<uint32_t> vMissingSignerIds;

    CCvnPartialSignatureUnsinged()
    {
        SetNull();
    }

    CCvnPartialSignatureUnsinged(const CCvnPartialSignatureUnsinged &sig)
    {
        this->nVersion          = sig.nVersion;
        this->nSignerId         = sig.nSignerId;
        this->nCreatorId        = sig.nCreatorId;
        this->hashPrevBlock     = sig.hashPrevBlock;
        this->signature         = sig.signature;
        this->fValidated        = sig.fValidated;
        this->vMissingSignerIds = sig.vMissingSignerIds;
        this->nCreationTime     = sig.nCreationTime;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nSignerId);
        READWRITE(nCreatorId);
        READWRITE(hashPrevBlock);
        READWRITE(signature);
        READWRITE(vMissingSignerIds);
        READWRITE(nCreationTime);
    }

    void SetNull()
    {
        nVersion      = CCvnPartialSignatureUnsinged::CURRENT_VERSION;
        nSignerId     = 0;
        nCreatorId    = 0;
        fValidated    = false;
        nCreationTime = 0;
        hashPrevBlock.SetNull();
        signature.SetNull();
        vMissingSignerIds.clear();
    }

    uint256 GetHash() const;

    string ToString() const;
};

class CCvnPartialSignature : public CCvnPartialSignatureUnsinged
{
public:
    CSchnorrSig msgSig;

    CCvnPartialSignature()
    {
        SetNull();
    }

    CCvnPartialSignature(const CCvnPartialSignatureUnsinged& signature)
        : CCvnPartialSignatureUnsinged(signature)
    {
        this->msgSig.SetNull();
    }

    void SetNull()
    {
        CCvnPartialSignatureUnsinged::SetNull();
        this->msgSig.SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CCvnPartialSignatureUnsinged*)this);
        READWRITE(msgSig);
    }

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
    inline void SerializationOp(Stream& s, Operation ser_action) {
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
    inline void SerializationOp(Stream& s, Operation ser_action) {
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

    CAmount nTransactionFee; // in µPLN
    CAmount nDustThreshold; // in µPLN

    /** for a node to create the next block it needs to have co-signed */
    /** the last nMinSuccessiveSignatures blocks */
    uint32_t nMinSuccessiveSignatures;

    /** The number of blocks to consider for calculation of the mean number of signature */
    uint32_t nBlocksToConsiderForSigCheck;

    /** minimum percentage of the number of nSignatureMean that are required to create the next block */
    uint32_t nPercentageOfSignaturesMean;

    /** The maximum allowed size for a serialised block */
    uint32_t nMaxBlockSize;

    /** The time (in sec.) to wait before CVNs start to create chain signatures again */
    uint32_t nBlockPropagationWaitTime;

    /** If a CVN has not received all partial signatures of a set it re-tries every
     ** nRetryNewSigSetInterval sec. to create a new set without the CVN IDs that were missing*/
    uint32_t nRetryNewSigSetInterval;

    /** Coinbase transaction outputs can only be spent after this number of new blocks */
    uint32_t nCoinbaseMaturity;

    /** A short description of the changes
     * A description string should be built like this:
     * #nnnnn <URI to a document where the decision is documented> <text that describes the change> */
    string strDescription;

    CDynamicChainParams()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
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
        READWRITE(nBlockPropagationWaitTime);
        READWRITE(nRetryNewSigSetInterval);
        READWRITE(nCoinbaseMaturity);
        READWRITE(strDescription);
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
        nBlockPropagationWaitTime = 0;
        nRetryNewSigSetInterval = 0;
        nCoinbaseMaturity = 0;
        strDescription = "";
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
    bool fFinalCoinsSupply;
    CScript scriptDestination;

    /** A short description of the changes
     * A description string should be built like this:
     * #nnnnn <URI to a document where the decision is documented> <text that describes the change> */
    string strDescription;

    CCoinSupply()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nValue);
        READWRITE(fFinalCoinsSupply);
        READWRITE(strDescription);
        READWRITE(*(CScriptBase*)(&scriptDestination));
    }

    void SetNull()
    {
        nVersion = CDynamicChainParams::CURRENT_VERSION;
        nValue = -1;
        fFinalCoinsSupply = false;
        strDescription = "";
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
    static const int32_t  FLUSH_SIGHOLDER_PAYLOAD = 1 << 4;
    static const int32_t       BLOCK_PAYLOAD_MASK = CVN_PAYLOAD | CHAIN_ADMINS_PAYLOAD | CHAIN_PARAMETERS_PAYLOAD | COIN_SUPPLY_PAYLOAD;
    uint32_t nPayload;
    uint32_t nCreationTime;

    // this chain data must be contained in the block after this hash
    uint256 hashPrevBlock;

    vector<CCvnInfo> vCvns;
    vector<CChainAdmin> vChainAdmins;
    CDynamicChainParams dynamicChainParams;

    // this is the multi sig of the chain administrators of the payload hash
    CSchnorrSig adminMultiSig;
    vector<uint32_t> vAdminIds;

    CCoinSupply coinSupply;

    CChainDataMsg()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nPayload);
        READWRITE(nCreationTime);
        READWRITE(hashPrevBlock);
        READWRITE(adminMultiSig);
        READWRITE(vAdminIds);

        if (HasCvnInfo())
            READWRITE(vCvns);
        if (HasChainAdmins())
            READWRITE(vChainAdmins);
        if (HasChainParameters())
            READWRITE(dynamicChainParams);
        if (HasCoinSupplyPayload())
            READWRITE(coinSupply);
    }

    void SetNull()
    {
        nPayload      = 0;
        nCreationTime = 0;
        hashPrevBlock.SetNull();
        adminMultiSig.SetNull();
        vAdminIds.clear();
        vCvns.clear();
        vChainAdmins.clear();
        dynamicChainParams.SetNull();
        coinSupply.SetNull();
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

    bool HasFlushSigholderPayload() const
    {
        return (nPayload & FLUSH_SIGHOLDER_PAYLOAD);
    }
};

class CNoncePoolUnsigned
{
public:
    uint32_t nCvnId;
    uint256  hashRootBlock;
    vector<CSchnorrNonce> vPublicNonces;
    uint32_t nCreationTime;

    CNoncePoolUnsigned()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nCvnId);
        READWRITE(hashRootBlock);
        READWRITE(nCreationTime);
        READWRITE(vPublicNonces);
    }

    void SetNull()
    {
        nCvnId        = 0;
        nCreationTime = 0;
        hashRootBlock.SetNull();
        vPublicNonces.clear();
    }

    uint256 GetHash() const;
    string ToString(const bool fVerbose = false) const;
};

class CNoncePool : public CNoncePoolUnsigned
{
public:
    CSchnorrSig msgSig;
    uint32_t    nHeightAdded; // memory only
    bool        fRecheck;     // memory only

    CNoncePool()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CNoncePoolUnsigned*)this);
        READWRITE(msgSig);
    }

    void SetNull()
    {
        CNoncePoolUnsigned::SetNull();
        msgSig.SetNull();
        nHeightAdded = 0;
        fRecheck     = false;
    }
};

class CAdminNonceUnsigned
{
public:
    uint32_t nAdminId;
    uint256  hashRootBlock;
    CSchnorrNonce publicNonce;
    uint32_t nCreationTime;

    CAdminNonceUnsigned()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nAdminId);
        READWRITE(hashRootBlock);
        READWRITE(nCreationTime);
        READWRITE(publicNonce);
    }

    void SetNull()
    {
        nAdminId      = 0;
        nCreationTime = 0;
        hashRootBlock.SetNull();
        publicNonce.SetNull();
    }

    uint256 GetHash() const;
    string ToString() const;
};

class CAdminNonce : public CAdminNonceUnsigned
{
public:
    CSchnorrSig msgSig;

    CAdminNonce()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CAdminNonceUnsigned*)this);
        READWRITE(msgSig);
    }

    void SetNull()
    {
        CAdminNonceUnsigned::SetNull();
        msgSig.SetNull();
    }
};

class CAdminPartialSignatureUnsinged
{
public:
    uint32_t nAdminId;
    uint256 hashRootBlock;
    uint256 hashChainData;
    CSchnorrSig signature;
    uint32_t nCreationTime;

    bool fValidated; // memory only

    // contains the admin IDs that co-signed
    vector<uint32_t> vSignerIds;

    CAdminPartialSignatureUnsinged()
    {
        SetNull();
    }

    CAdminPartialSignatureUnsinged(const CAdminPartialSignatureUnsinged &sig)
    {
        this->nAdminId      = sig.nAdminId;
        this->hashRootBlock = sig.hashRootBlock;
        this->hashChainData = sig.hashChainData;
        this->signature     = sig.signature;
        this->fValidated    = sig.fValidated;
        this->nCreationTime = sig.nCreationTime;
        this->vSignerIds    = sig.vSignerIds;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nAdminId);
        READWRITE(hashRootBlock);
        READWRITE(hashChainData);
        READWRITE(signature);
        READWRITE(nCreationTime);
        READWRITE(vSignerIds);
    }

    void SetNull()
    {
        nAdminId      = 0;
        fValidated    = false;
        nCreationTime = 0;
        hashRootBlock.SetNull();
        hashChainData.SetNull();
        signature.SetNull();
        vSignerIds.clear();
    }

    uint256 GetHash() const;

    string ToString() const;
};

class CAdminPartialSignature : public CAdminPartialSignatureUnsinged
{
public:
    CSchnorrSig msgSig;

    CAdminPartialSignature()
    {
        SetNull();
    }

    CAdminPartialSignature(const CAdminPartialSignatureUnsinged& signature)
        : CAdminPartialSignatureUnsinged(signature)
    {
        this->msgSig.SetNull();
    }

    void SetNull()
    {
        CAdminPartialSignatureUnsinged::SetNull();
        this->msgSig.SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CAdminPartialSignatureUnsinged*)this);
        READWRITE(msgSig);
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
