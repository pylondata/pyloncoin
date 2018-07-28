// Copyright (c) 2017 The Pyloncoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SMARTCARD_H
#define BITCOIN_SMARTCARD_H

#include "primitives/block.h"
#include "SerialConnection.h"
#include "key.h"

enum CFasitoKeyStatus {
    EMPTY,
    SEEDED,
    CONFIGURED,
};

class CFasitoKey
{
public:
    uint32_t nCvnId;
    CSchnorrPubKey pubKey;
    CFasitoKeyStatus status;
    uint8_t nKeyIndex;
    bool fProtected;

    CFasitoKey()
    {
        SetNull();
    }

    void SetNull()
    {
        nCvnId = 0;
        pubKey.SetNull();
        status = EMPTY;
        nKeyIndex = 0;
        fProtected = false;
    }

    std::string ToString() const;
};

class CFasito : public SerialConnection
{
public:
    bool fInitialized;
    bool fLoggedIn;

    string strFasitoVersion;
    string strSerialNumber;
    string strTokenStatus;
    string strProtectionStatus;
    string strConfigVersion;
    string strConfigChecksum;
    uint32_t nNoncePoolSize;
    string strPinStatus;
    map<uint8_t, CFasitoKey> mapKeys;

    uint8_t nCVNKeyIndex;
    uint8_t nADMINKeyIndex;

    vector<uint8_t> vNonceHandles;

    CFasito()
    {
        SetNull();
    }

    void SetNull()
    {
        fInitialized = false;
        fLoggedIn = false;
        strFasitoVersion.clear();
        strSerialNumber.clear();
        strTokenStatus.clear();
        strProtectionStatus.clear();
        strConfigVersion.clear();
        strConfigChecksum.clear();
        nNoncePoolSize = 0;
        strPinStatus.clear();
        mapKeys.clear();
        nCVNKeyIndex = 0;
        nADMINKeyIndex = 0;
        vNonceHandles.clear();
    }

    void open(const std::string& devname);
    void close();
    bool login(const string& strPassword, string &strError);
    bool logout();
    void emtpyInputBuffer();
};

extern bool InitFasito(const string& strPassword, string& strError);
extern uint32_t InitCVNWithFasito(const string &strFasitoPassword);
extern bool CreateNonceWithFasito(const uint256& hashData, const uint8_t nKey, unsigned char *pPrivateData, CSchnorrNonce& noncePublic, const CSchnorrPubKey& pubKey);
extern bool CvnSignWithFasito(const uint256 &hashToSign, const uint8_t nKey, CSchnorrSig& signaturee);
extern bool CvnSignPartialWithFasito(const uint256& hashUnsignedBlock, const uint8_t nKey, const CSchnorrPubKey& sumPublicNoncesOthers, CSchnorrSig& signature, const int nPoolOffset);
extern bool AdminSignPartialWithFasito(const uint256& hashToSign, const uint8_t nKey, const CSchnorrPubKey& sumPublicNoncesOthers, CSchnorrSig& signature, const uint8_t nHandle);
extern uint32_t InitChainAdminWithFasito(const string& strPassword, const uint32_t nKeyIndex, string &strError);
extern bool FasitoInitPrivKey(const CKey& privKey, const uint32_t nKeyIndex, const uint32_t nId);

extern CFasito fasito;

#endif // BITCOIN_SMARTCARD_H
