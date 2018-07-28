// Copyright (c) 2017 The Pyloncoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "SerialConnection.h"
#include "primitives/block.h"
#include "poc.h"
#include "init.h"
#include "fasito.h"

#include <secp256k1.h>
#include <openssl/ssl.h>

#include <iostream>
#include <stdint.h>

#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

#define FASITO_DEBUG 0

CFasito fasito;

static string bin2hex(const uint8_t *buf, const size_t len)
{
    size_t i;
    char c[3];
    string res;

    for (i = 0; i < len; i++) {
        sprintf(c, "%02x", buf[i]);
        res.append(c);
    }

    return res;
}

bool CreateNonceWithFasito(const uint256& hashData, const uint8_t nKey, unsigned char *pPrivateData, CSchnorrNonce& noncePublic, const CSchnorrPubKey& pubKey)
{
    if (!fasito.mapKeys.count(nKey) || fasito.mapKeys[nKey].pubKey != pubKey) {
        LogPrintf("CreateNonceWithFasito : public key in Fasito does not match cvnInfo in blockchain: %s != %s\n", fasito.mapKeys[nKey].pubKey.ToString(), pubKey.ToString());
        return false;
    }

    CHashWriter hasher(SER_GETHASH, 0);
    hasher << GetTimeMillis() << string("we need random nonces") << rand();

    std::stringstream s;
    s << strprintf("NONCE %d %s %s", nKey, bin2hex(&hashData.begin()[0], 32), bin2hex(&hasher.GetHash().begin()[0], 32));

    vector<string> res;
    try {
        if (!fasito.sendAndReceive(s.str(), res)) {
            LogPrintf("CreateNonceWithFasito : could not create nonce pair: %s\n", (!res.empty() ? res[0] : "error not available"));
            return false;
        }
        int nHandle = atoi(res[0].substr(0,2).c_str());
        *((uint8_t *)pPrivateData) = (uint8_t)nHandle;

        vector<uint8_t> pubNonce = ParseHex(res[0].substr(3));
        memcpy(&noncePublic.begin()[0], &pubNonce.begin()[0], 64);
    } catch(const std::exception &e) {
        LogPrintf("failed to send NONCE command: %s\n", e.what());
        return false;
    }

#if FASITO_DEBUG
    LogPrintf("CreateNonceWithFasito : OK\n  Hash: %s\n  pubk: %s\n  nKey: %d\n   sig: %s\n",
            hashData.ToString(),
            fasito.mapKeys[nKey].pubKey.ToString(),
            nKey,
            noncePublic.ToString());
#endif
    return true;
}

bool CvnSignWithFasito(const uint256 &hashToSign, const uint8_t nKey, CSchnorrSig& signature)
{
    if (!fasito.mapKeys.count(nKey)) {
        LogPrintf("CvnSignWithFasito : public key #%d not found\n", nKey);
        return false;
    }

    std::stringstream s;

    s << strprintf("SCHNORR %d %s", nKey, bin2hex(&hashToSign.begin()[0], 32));
    vector<string> res;
    vector<uint8_t> vSig;
    try {
        if (!fasito.sendAndReceive(s.str(), res)) {
            LogPrintf("CvnSignWithFasito : could not sign hash: %s\n", (!res.empty() ? res[0] : "error not available"));
            return false;
        }
        vSig = ParseHex(res[0]);

        memcpy(&signature.begin()[0], &vSig.begin()[0], 64);
    } catch(const std::exception &e) {
        LogPrintf("failed to send SCHNORR command: %s\n", e.what());
        return false;
    }

    if (!CvnVerifySignature(hashToSign, signature, fasito.mapKeys[nKey].pubKey)) {
        LogPrintf("CvnSignWithFasito : created invalid signature\n");
        return false;
    }

#if FASITO_DEBUG
    LogPrintf("CvnSignWithFasito : OK\n  Hash: %s\n  pubk: %s\n  nKey: %d\n   sig: %s\nrawsig: %s\nhexstr: %s\n",
            hashToSign.ToString(),
            fasito.mapKeys[nKey].pubKey.ToString(),
            nKey, signature.ToString(), res[0], HexStr(vSig));
#endif
   return true;
}

bool CvnSignPartialWithFasito(const uint256& hashToSign, const uint8_t nKey, const CSchnorrPubKey& sumPublicNoncesOthers, CSchnorrSig& signature, const int nPoolOffset)
{
    if (!fasito.mapKeys.count(nKey)) {
        LogPrintf("CvnSignPartialWithFasito : public key #%d not found.\n", nKey);
        return false;
    }

    uint8_t nHandle = fasito.vNonceHandles[nPoolOffset];

    std::stringstream s;
    s << strprintf("PARTSIG %d %d %s %s", nKey, nHandle, bin2hex(&hashToSign.begin()[0], 32), bin2hex(&sumPublicNoncesOthers.begin()[0], 64));
    vector<string> res;

    try {
        if (!fasito.sendAndReceive(s.str(), res)) {
            LogPrintf("CvnSignPartialWithFasito : could not partial sign hash: %s\nCOMMAND: %s\n", (!res.empty() ? res[0] : "error not available"), s.str());
            return false;
        }
        vector<uint8_t> vSig = ParseHex(res[0]);

        memcpy(&signature.begin()[0], &vSig.begin()[0], 64);
    } catch(const std::exception &e) {
        LogPrintf("failed to send PARTSIG command: %s\n", e.what());
        return false;
    }

#if FASITO_DEBUG
    LogPrintf("CvnSignPartialWithFasito : OK\n  Hash: %s\nsigner: 0x%08x\n   sum: %s\n   sig: %s\n",
            hashToSign.ToString(), signature.nSignerId,
            sumPublicNoncesOthers.ToString(), signature.ToString());
#endif
    return true;
}

bool AdminSignPartialWithFasito(const uint256& hashToSign, const uint8_t nKey, const CSchnorrPubKey& sumPublicNoncesOthers, CSchnorrSig& signature, const uint8_t nHandle)
{
    if (!fasito.mapKeys.count(nKey)) {
        LogPrintf("%s : public key #%d not found.\n", __func__, nKey);
        return false;
    }

    std::stringstream s;
    s << strprintf("PARTSIG %d %d %s %s", nKey, nHandle, bin2hex(&hashToSign.begin()[0], 32), bin2hex(&sumPublicNoncesOthers.begin()[0], 64));
    vector<string> res;

    try {
        if (!fasito.sendAndReceive(s.str(), res)) {
            LogPrintf("%s : could not partial sign hash: %s\nCOMMAND: %s\n", __func__, (!res.empty() ? res[0] : "error not available"), s.str());
            return false;
        }
        vector<uint8_t> vSig = ParseHex(res[0]);

        memcpy(&signature.begin()[0], &vSig.begin()[0], 64);
    } catch(const std::exception &e) {
        LogPrintf("%s : failed to send PARTSIG command: %s\n", __func__, e.what());
        return false;
    }

#if FASITO_DEBUG
    LogPrintf("%s : OK\n  Hash: %s\nsigner: 0x%08x\n   sum: %s\n   sig: %s\n", __func__,
            hashToSign.ToString(), signature.nSignerId,
            sumPublicNoncesOthers.ToString(), signature.ToString());
#endif
    return true;
}

string CFasitoKey::ToString() const
{
    std::stringstream s;
    s << strprintf("CFasitoKey(cvnId=0x%08x, CFasitoKeyStatus=%u, nKeyIndex=%u, protected=%S) : %s",
        nCvnId,
        status, nKeyIndex,
        (fProtected ? "true" : "false"), pubKey.ToString()
    );
    return s.str();
}

bool CFasito::login(const string& strPassword, string &strError)
{
    if (!fInitialized)
        return false;

    if (fLoggedIn)
        return true;

    fLoggedIn = false;
    vector<string> res;
    try {
        if (!fasito.sendAndReceive("LOGIN " + strPassword, res)) {
            strError = !res.empty() ? res[0] : "error not available";
            return false;
        }
    } catch(const std::exception &e) {
        strprintf(strError, "failed to send login command: %s", e.what());
        return false;
    }

    fLoggedIn = true;
    return true;
}

bool CFasito::logout()
{
    if (!fInitialized)
        return false;

    if (!fLoggedIn)
        return true;

    try {
        fLoggedIn = false;
        LogPrintf("logging out from Fasito.\n");
        if (fasito.sendCommand("LOGOUT"))
            return true;
        else
            LogPrintf("Could not logout from Fasito\n");
    } catch(const std::exception &e) {
        LogPrintf("failed to send login command: %s\n", e.what());
    }

    fLoggedIn = true;
    return false;
}

void CFasito::emtpyInputBuffer()
{
    setTimeout(boost::posix_time::millisec(200));
    writeString("\r");

    try {
        while (true) {
            readStringUntil("\r\n");
        }
    } catch(const std::exception &e) {

    }
}

/*
Serial number     : 012345678999
Token status      : CONFIGURED
Protection status : 0x01100010
Config version    : 1
Config checksum   : 1234

User PIN          : SET (tries left: 3)

Key #0            : 0x70000001 (CONFIGURED)
Key #1            : 0x70000002 (CONFIGURED)
Key #2            : 0x00000000 (SEEDED)
Key #3            : 0x00000000 (SEEDED)
Key #4            : 0x00000000 (SEEDED)
Key #5            : 0x00000000 (SEEDED)
Key #6            : 0x00000000 (SEEDED)
Key #7            : 0x00000000 (CONFIGURED, protected)
 */

#define VALUE_OFFSET 20

void CFasito::open(const string &devname)
{
    LOCK(cs_connection);
    SerialConnection::open(devname, 230400);

    emtpyInputBuffer();

    int i = 0;
    vector<string> res;
    if (!sendAndReceive("INFO", res)) {
        LogPrintf("CFasito::open : could not get device info: %s\n", (!res.empty() ? res[0] : "error not available"));
        fInitialized = false;
        return;
    }
    strFasitoVersion    = res[i++].substr(VALUE_OFFSET);
    strSerialNumber     = res[i++].substr(VALUE_OFFSET);
    strTokenStatus      = res[i++].substr(VALUE_OFFSET);
    strProtectionStatus = res[i++].substr(VALUE_OFFSET);
    strConfigVersion    = res[i++].substr(VALUE_OFFSET);
    strConfigChecksum   = res[i++].substr(VALUE_OFFSET);
    nNoncePoolSize      = atoi(res[i++].substr(VALUE_OFFSET).c_str());
    ++i;
    strPinStatus        = res[i++].substr(VALUE_OFFSET);
    ++i;

    int nKey = 0;
    while (1) {
        string line = res[i++];
        if (!boost::algorithm::starts_with(line, "Key #"))
            break;

        string keyStatus = line.substr(VALUE_OFFSET);

        CFasitoKey key;
        stringstream ss;
        ss << hex << keyStatus.substr(0, 10);
        ss >> key.nCvnId;

        string status = keyStatus.substr(12, keyStatus.length() - 13);

        if (status == "EMPTY")
            key.status = EMPTY;
        else if (status == "SEEDED")
            key.status = SEEDED;
        else if (status == "CONFIGURED")
            key.status = CONFIGURED;
        else if (status == "CONFIGURED, protected") {
            key.status = CONFIGURED;
            key.fProtected = true;
        } else
            LogPrintf("unknown status for Key #%d: %s\n", nKey, status);

        key.nKeyIndex = nKey++;
        mapKeys[key.nKeyIndex] = key;
    }

    fInitialized = true;
}

void CFasito::close()
{
    LOCK(cs_connection);

    if (fLoggedIn)
        logout();

    if (fInitialized)
        SerialConnection::close();

    fInitialized = false;
}

static void RetrievePubKeys()
{
    string strGetPubKey  = "GETPBKY #";
    BOOST_FOREACH(PAIRTYPE(const uint8_t, CFasitoKey) &entry, fasito.mapKeys) {
        CFasitoKey& k = entry.second;
        if (k.status == CONFIGURED && !k.fProtected) {
            strGetPubKey[8] = '0' + (char)k.nKeyIndex;
            vector<string> res;
            if (!fasito.sendAndReceive(strGetPubKey, res)) {
                LogPrintf("RetrievePubKeys : could not retrieve public key: %s\n", (!res.empty() ? res[0] : "error not available"));
                continue;
            }
            vector<uint8_t> derKey = ParseHex(res[0]);

            CPubKey testKey(derKey);
            if (!testKey.IsFullyValid()) {
                LogPrintf("Fasito key #%d is invalid: %s\n", k.nKeyIndex, res[0]);
                continue;
            }

            k.pubKey = CSchnorrPubKeyDER(res[0]);
            LogPrint("fasito", "public key #%d: %s\n", k.nKeyIndex, k.ToString());
        }
    }
}

bool InitFasito(const string& strPassword, string& strError)
{
    const string strDevice = GetArg("-fasitodevice", "/dev/ttyACM0");

    try {
        fasito.open(strDevice);
        fasito.setTimeout(boost::posix_time::seconds(2));

        LogPrintf("detected Fasito %s, serial number: %s, user-PIN status: %s, protection status: %s\n",
                fasito.strFasitoVersion, fasito.strSerialNumber, fasito.strPinStatus, fasito.strProtectionStatus);

        if (fasito.strTokenStatus != "CONFIGURED") {
            strError = "Fasito not configured";
            return false;
        }

        if (boost::algorithm::starts_with(fasito.strPinStatus, "LOCKED")) {
            strError = "Fasito is locked";
            return false;
        }

        size_t nPassLen = strPassword.length();
        if (strPassword.empty()) {
            strError = "no PIN supplied";
            return false;
        }

        if (nPassLen != 6) {
            strError = "invalid PIN length";
            return false;
        }

        if (!fasito.login(strPassword, strError)) {
            return false;
        }

        /* Retrieve the public keys */
        RetrievePubKeys();
    } catch (const std::exception& e) {
        strError = "could not open device: " + strDevice;

        if (fasito.fInitialized)
            fasito.close();
        return false;
    }

    return true;
}

uint32_t InitCVNWithFasito(const string &strFasitoPassword)
{
    string strError;
    if (!InitFasito(strFasitoPassword, strError)) {
        LogPrintf("%s: %s\n", __func__, strError);
        return 0;
    }

    uint32_t nKeyIndex = GetArg("-fasitocvnkeyindex", 0);
    if (nKeyIndex > 6) {
        LogPrintf("invalid value for -fasitocvnkeyindex\n");
        fasito.close();
        return 0;
    }

    if (!fasito.mapKeys.count(nKeyIndex)) {
        LogPrintf("key #%d not found on Fasito\n", nKeyIndex);
        fasito.close();
        return 0;
    }

    CFasitoKey &fasitoKeys = fasito.mapKeys[nKeyIndex];
    if (fasitoKeys.status != CONFIGURED) {
        LogPrintf("key #%d not configured on Fasito\n", nKeyIndex);
        fasito.close();
        return 0;
    }
    fasito.nCVNKeyIndex = nKeyIndex;
    CFasitoKey fKey = fasito.mapKeys[nKeyIndex];

    vector<unsigned char> vPubKey;
    fKey.pubKey.GetPubKeyDER(vPubKey);

    LogPrintf("Using Fasito for CVN ID 0x%08x with public key %s\n", fKey.nCvnId, HexStr(vPubKey));
    return fKey.nCvnId;
}

uint32_t InitChainAdminWithFasito(const string& strPassword, const uint32_t nKeyIndex, string &strError)
{
    bool fWasInitialised = true;
    if (!fasito.fInitialized) {
        if (!InitFasito(strPassword, strError)) {
            LogPrintf("%s\n", strError);
            fasito.close();
            return 0;
        }

        fWasInitialised = false;
    }

    if (nKeyIndex > 6) {
        strprintf(strError, "invalid value for adminkeyindex: %d", nKeyIndex);
        LogPrintf("%s\n", strError);
        if (!fWasInitialised)
            fasito.close();
        return 0;
    }

    if (!fasito.mapKeys.count(nKeyIndex)) {
        strprintf(strError, "key #%d not found on Fasito", nKeyIndex);
        LogPrintf("%s\n", strError);
        if (!fWasInitialised)
            fasito.close();
        return 0;
    }

    CFasitoKey &fasitoKeys = fasito.mapKeys[nKeyIndex];
    if (fasitoKeys.status != CONFIGURED) {
        strprintf(strError, "key #%d not configured on Fasito", nKeyIndex);
        LogPrintf("%s\n", strError);
        if (!fWasInitialised)
            fasito.close();
        return 0;
    }

    fasito.nADMINKeyIndex = nKeyIndex;
    CFasitoKey fKey = fasito.mapKeys[nKeyIndex];

    vector<unsigned char> vPubKey;
    fKey.pubKey.GetPubKeyDER(vPubKey);

    LogPrintf("Using Fasito for ADMIN ID 0x%08x with public key %s\n", fKey.nCvnId, HexStr(vPubKey));
    return fKey.nCvnId;
}

bool FasitoInitPrivKey(const CKey& privKey, const uint32_t nKeyIndex, const uint32_t nId)
{
    std::stringstream strInitKeyCmd;
    strInitKeyCmd << strprintf("INITKEY %d 0x%08x %s", nKeyIndex, nId, bin2hex(&privKey.begin()[0], 32));

    vector<string> res;
    if (!fasito.sendAndReceive(strInitKeyCmd.str(), res)) {
        LogPrintf("FasitoInitPrivKey : could not initialise private key: %s\n", (!res.empty() ? res[0] : "error not available"));
        return false;
    }

    return true;
}
