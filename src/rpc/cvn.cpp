// Copyright (c) 2016-2017 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockfactory.h"
#include "base58.h"
#include "util.h"
#include "main.h"
#include "utilstrencodings.h"
#include "poc.h"
#include "fasito/fasito.h"
#include "fasito/cert.h"
#include "core_io.h"
#include "timedata.h"
#include "validationinterface.h"
#include "consensus/validation.h"
#include "consensus/consensus.h"

#include <boost/algorithm/string.hpp>
#include <univalue.h>
#include "server.h"

using namespace std;

static string strMethod;
static uint8_t nAdminNonceHandle = 0;
static CSchnorrPrivNonce adminPrivNonce;
static CSchnorrNonce adminPublicNonce;

static bool AddAdminSignatures(CChainDataMsg &msg)
{
    if (mapAdminSigs.empty()) {
        return false;
    }

    CAdminPartialSignature sigFirst = mapAdminSigs.begin()->second;
    if (sigFirst.vSignerIds.size() != mapAdminSigs.size()) {
        return false;
    }

    const uint32_t nSigs = mapAdminSigs.size();
    const uint256 hash2Sign = msg.GetHash();

    if (nSigs < dynParams.nMinAdminSigs)
        throw runtime_error(
            strprintf("not enough signatures supplied "
                      "(got %u signatures, but need at least %u to sign)", nSigs, dynParams.nMinAdminSigs));
    if (nSigs > dynParams.nMaxAdminSigs || nSigs > MAX_NUMBER_OF_CHAIN_ADMINS)
        throw runtime_error(
            strprintf("too many signatures supplied %u (%u max)\nReduce the number", nSigs, dynParams.nMaxAdminSigs));

    if (msg.HasCoinSupplyPayload() && nSigs < dynParams.nMaxAdminSigs)
        throw runtime_error(
                strprintf("not enough signatures supplied "
                       "(got %u signatures, but need at least %u to sign for coin supply)", nSigs, dynParams.nMaxAdminSigs));

    if (mapChainAdmins.size() == 1 || (dynParams.nMinAdminSigs && mapAdminNonces.size() == 1)) {
        msg.vAdminIds     = sigFirst.vSignerIds;
        msg.adminMultiSig = sigFirst.signature;
        return CheckAdminSignature(msg.vAdminIds, msg.GetHash(), msg.adminMultiSig, msg.HasCoinSupplyPayload());
    }

    int count = 0;
    bool fAllSigsValid = true;
    uint8_t *sigs[MAX_NUMBER_OF_CHAIN_ADMINS];
    set<uint32_t> setSigners;

    BOOST_FOREACH(const MapSigAdmin::value_type& entry, mapAdminSigs) {
        const CAdminPartialSignature& sig = entry.second;

        if (!sig.fValidated && !VerifyPartialAdminSignature(sig, hash2Sign)) {
            LogPrintf("Invalid signature found.\n%s\n", sig.ToString());
            fAllSigsValid = false;
        }

        if (!setSigners.insert(entry.first).second) {
            LogPrintf("duplicate signature detected: %s\n%s\n", sig.ToString(), sigHolder.ToString());
            fAllSigsValid = false;
        }

        if (sig.hashRootBlock != chainActive.Tip()->GetBlockHash()) {
            LogPrintf("Invalid signature found for wrong tip.\n%s\n", sig.ToString());
            fAllSigsValid = false;
        }

        if (sig.hashChainData != hash2Sign) {
            LogPrintf("Invalid signature found for wrong chain data hash.\n%s\n", sig.ToString());
            fAllSigsValid = false;
        }

        if (sig.vSignerIds != sigFirst.vSignerIds) {
            LogPrintf("Invalid signature found for for different signer set.\n%s\nCommon Rx: %s\n", sig.ToString(), sig.signature.GetRx().ToString());
            fAllSigsValid = false;
        }

        sigs[count++] = (uint8_t *)&sig.signature.begin()[0];
    }

    if (!fAllSigsValid)
        return false;

    LogPrint("cvnsig", "all %d partial admin signatures in set found valid.\n", setSigners.size());

    CSchnorrSig multiSig;
    int ret = CombinePartialSignatures(multiSig, sigs, count);
    if (ret != 1) {
        LogPrintf("could not combine admin signatures: %d\n", ret);
        return false;
    }

    msg.vAdminIds     = sigFirst.vSignerIds;
    msg.adminMultiSig = multiSig;

    return CheckAdminSignature(msg.vAdminIds, msg.GetHash(), msg.adminMultiSig, msg.HasCoinSupplyPayload());
}

static bool AddAdminIds(CChainDataMsg &msg)
{
    if (mapAdminNonces.empty()) {
        return false;
    }

    BOOST_FOREACH(const CNoncesMapType::value_type& nonce, mapAdminNonces) {
        msg.vAdminIds.push_back(nonce.first);
    }

    return true;
}

static void AddCvnInfoToMsg(CChainDataMsg &msg, const uint32_t nNodeId, const uint32_t nHeightAdded, const CSchnorrPubKey &pubKey)
{
    msg.nPayload |= CChainDataMsg::CVN_PAYLOAD;
    msg.vCvns.resize(mapCVNs.size() + 1);

    uint32_t index = 0;
    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs) {
        msg.vCvns[index++] = cvn.second;
    }

    CCvnInfo cvn(nNodeId, nHeightAdded, pubKey);
    msg.vCvns[index] = cvn;
}

static void AddChainAdminToMsg(CChainDataMsg &msg, const uint32_t nAdminId, const uint32_t nHeightAdded, const CSchnorrPubKey &pubKey)
{
    msg.nPayload |= CChainDataMsg::CHAIN_ADMINS_PAYLOAD;
    msg.vChainAdmins.resize(mapChainAdmins.size() + 1);

    uint32_t index = 0;
    BOOST_FOREACH(const ChainAdminMapType::value_type& cvn, mapChainAdmins) {
        msg.vChainAdmins[index++] = cvn.second;
    }

    CChainAdmin admin(nAdminId, nHeightAdded, pubKey);
    msg.vChainAdmins[index] = admin;
}

static bool AddDynParamsToMsg(CChainDataMsg& msg, UniValue jsonParams)
{
    LogPrintf("AddDynParamsToMsg : adding %u parameters\n", jsonParams.getKeys().size());

    //TODO: only for development, remove in production release
    UniValue flushSigholder = find_value(jsonParams, "flushSigholder");
    if (!flushSigholder.isNull()) {
        if (flushSigholder.isTrue()) {
            msg.nPayload = CChainDataMsg::FLUSH_SIGHOLDER_PAYLOAD;
            return true;
        } else
            return false;
    }

    msg.nPayload = CChainDataMsg::CHAIN_PARAMETERS_PAYLOAD;

    CDynamicChainParams& params = msg.dynamicChainParams;

    params.nVersion                     = dynParams.nVersion;
    params.nBlockSpacing                = dynParams.nBlockSpacing;
    params.nBlockSpacingGracePeriod     = dynParams.nBlockSpacingGracePeriod;
    params.nTransactionFee              = dynParams.nTransactionFee;
    params.nDustThreshold               = dynParams.nDustThreshold;
    params.nMaxAdminSigs                = dynParams.nMaxAdminSigs;
    params.nMinAdminSigs                = dynParams.nMinAdminSigs;
    params.nMinSuccessiveSignatures     = dynParams.nMinSuccessiveSignatures;
    params.nBlocksToConsiderForSigCheck = dynParams.nBlocksToConsiderForSigCheck;
    params.nPercentageOfSignaturesMean  = dynParams.nPercentageOfSignaturesMean;
    params.nMaxBlockSize                = dynParams.nMaxBlockSize;
    params.nBlockPropagationWaitTime    = dynParams.nBlockPropagationWaitTime;
    params.nRetryNewSigSetInterval      = dynParams.nRetryNewSigSetInterval;

    bool fAllGood = true;
    vector<string> paramsList = jsonParams.getKeys();
    BOOST_FOREACH(const string& key, paramsList) {
        LogPrintf("%s : adding %s: %u\n", __func__, key, jsonParams[key].getValStr());
        if (key == "blockSpacing") {
            params.nBlockSpacing = jsonParams[key].get_int();
        } else if (key == "blockSpacingGracePeriod") {
            params.nBlockSpacingGracePeriod = jsonParams[key].get_int();
        } else if (key == "transactionFee") {
            params.nTransactionFee = AmountFromValue(jsonParams[key]);
        } else if (key == "dustThreshold") {
            params.nDustThreshold = AmountFromValue(jsonParams[key]);
        } else if (key == "maxAdminSigs") {
            params.nMaxAdminSigs = jsonParams[key].get_int();
        } else if (key == "minAdminSigs") {
            params.nMinAdminSigs = jsonParams[key].get_int();
        } else if (key == "minSuccessiveSignatures") {
            params.nMinSuccessiveSignatures = jsonParams[key].get_int();
        } else if (key == "blocksToConsiderForSigCheck") {
            params.nBlocksToConsiderForSigCheck = jsonParams[key].get_int();
        } else if (key == "percentageOfSignaturesMean") {
            params.nPercentageOfSignaturesMean = jsonParams[key].get_int();
        } else if (key == "maxBlockSize") {
            params.nMaxBlockSize = jsonParams[key].get_int();
        } else if (key == "blockPropagationWaitTime") {
            params.nBlockPropagationWaitTime = jsonParams[key].get_int();
        } else if (key == "retryNewSigSetInterval") {
            params.nRetryNewSigSetInterval = jsonParams[key].get_int();
        } else if (key == "description") {
            params.strDescription = jsonParams[key].get_str();
        } else {
            LogPrintf("parameter %s is invalid\n", key);
            fAllGood = false;
        }
    }

    if (params.strDescription.length() <= MIN_CHAIN_DATA_DESCRIPTION_LEN) {
        LogPrintf("%s : missing mandatory description\n", __func__);
        return false;
    }

    return fAllGood;
}

UniValue getgenerate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getgenerate\n"
            "\nReturn if the server is set to generate blocks or not. The default is false.\n"
            "It is set with the command line argument -gen (or " + std::string(BITCOIN_CONF_FILENAME) + " setting gen)\n"
            "It can also be set with the setgenerate call.\n"
            "\nResult\n"
            "true|false      (boolean) If the server is set to generate blocks or not\n"
            "\nExamples:\n"
            + HelpExampleCli("getgenerate", "")
            + HelpExampleRpc("getgenerate", "")
        );

    LOCK(cs_main);
    return GetBoolArg("-gen", DEFAULT_GENERATE);
}

UniValue setgenerate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 )
        throw runtime_error(
            "setgenerate generate\n"
            "\nSet 'generate' true or false to turn generation on or off.\n"
            "See the getgenerate call for the current setting.\n"
            "\nArguments:\n"
            "1. generate         (boolean, required) Set to true to turn on generation, off to turn off.\n"
            "\nExamples:\n"
            "\nSet the generation on\n"
            + HelpExampleCli("setgenerate", "true") +
            "\nCheck the setting\n"
            + HelpExampleCli("getgenerate", "") +
            "\nTurn off generation\n"
            + HelpExampleCli("setgenerate", "false")
        );

    if (Params().CreateBlocksOnDemand())
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Use the generate method instead of setgenerate on this network");

    if (!nCvnNodeId)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "CVN not configured. Can not start or stop CVN process");

    bool fGenerate = true;
    if (params.size() > 0)
        fGenerate = params[0].get_bool();

    mapArgs["-gen"] = (fGenerate ? "1" : "0");
    RunPOCThread(fGenerate, Params(), nCvnNodeId);

    return NullUniValue;
}

UniValue chainadminlogin(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "chainadminlogin type PIN\n"
            "\nLogin to Fasito or read the admin certificate file.\n"
            "\nArguments:\n"
            "1. method      (string, required) Signing method: 'fasito' or 'file'.\n"
            "2. PIN         (string, required) The PIN to unlock the Fasito or to decrypt the private key file.\n"
            "3. key index   (numeric, optinal) The index of the key on Fasito. (default is 0)\n"
            "\nExamples:\n"
            "\nLogin to Fasito\n"
            + HelpExampleCli("chainadminlogin", "fasito 123456 0")
            + HelpExampleCli("chainadminlogin", "file mySecretPassword")
        );

    LOCK(cs_main);
    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "wait for block chain download to finish");

    if (nChainAdminId)
        throw JSONRPCError(RPC_MISC_ERROR, "already logged in");

    string method = params[0].get_str();
    const string strPassword = params[1].get_str();

    if (method == "fasito") {
        if (params.size() < 2) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Fasito PIN not supplied\n");
        }
#ifdef USE_FASITO
        LogPrintf("Initializing fasito for chain adminstration\n");
        const uint32_t nKeyIndex = params.size() == 3 ? params[2].get_int() : 0;
        nChainAdminId = InitChainAdminWithFasito(strPassword, nKeyIndex);
#else
        return "ERROR: This wallet version was not compiled with fasito support\n";
#endif
    } else if (method == "file") {
        nChainAdminId = InitChainAdminWithCertificate(strPassword);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMS, "invalid signing method. Must be one of 'fasito' or 'file'\n");
    }

    if (!nChainAdminId) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "could not find a vaild chain admin ID\n");
    }

    LogPrintf("Configuring node with chain admin ID 0x%08x\n", nChainAdminId);

    strMethod = method;

    return "OK";
}

UniValue chainadminlogout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size())
        throw runtime_error(
            "chainadminlogout\n"
            "\nLogout from Fasito.\n"
            "\nArguments:\n"
            "none\n"
            "\nExample:\n"
            "\nLogout from Fasito\n"
            "chainadminlogout"
        );

    LOCK(cs_main);

    if (strMethod == "fasito") {
#ifdef USE_FASITO
        if (!nCvnNodeId) {
            fasito.close();
        } else {
            throw JSONRPCError(RPC_MISC_ERROR, "cannot log off because the node is configured as a CVN\n");
        }
#else
        return "ERROR: This wallet version was not compiled with fasito support\n";
#endif
    }

    LogPrintf("Removed chain admin configuration for admin ID 0x%08x\n", nChainAdminId);

    nChainAdminId = 0;
    adminPrivKey = CKey();
    adminPubKey.SetNull();
    strMethod.clear();

    return "OK";
}

UniValue chainadminnonce(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size())
        throw runtime_error(
            "chainadminnonce\n"
            "\nCreates a nonce pair and publishes the public part on the network.\n"
            "\nArguments:\n"
            "none\n"
            "\nExample:\n"
            "\nCreate a nonce pair\n"
            "chainadminlogin"
        );

    bool fFasito = strMethod == "fasito";

    if (!nChainAdminId || (!fFasito && !adminPrivKey.IsValid()))
        return "ERROR: wallet not configured for chain administration";

    LOCK(cs_main);
    uint256 hashRootBlock = chainActive.Tip()->GetBlockHash();

    CAdminNonce msg;

    msg.hashRootBlock = hashRootBlock;
    msg.nAdminId = nChainAdminId;
    msg.nCreationTime = GetTime();

    uint256 hashData;
    GetStrongRandBytes(&hashData.begin()[0], 32);
    unsigned char privateData[32];
    if (!CreateNoncePairForHash(adminPublicNonce, privateData, hashData, nChainAdminId, fFasito, true)) {
        return "could not create nonce";
    }

    msg.publicNonce = adminPublicNonce;

    if (fFasito) {
        uint32_t *nHandle = (uint32_t *) &privateData[0];
        nAdminNonceHandle = *nHandle;
    } else {
        CSchnorrPrivNonce pn(privateData);
        adminPrivNonce = pn;
    }

    // sign the message
    CSchnorrSig msgSig;
    if (!AdminSignHash(msg.GetHash(), msgSig, fFasito)) {
        return strprintf("%s : could not sign signature message\n", __func__);
    }

    msg.msgSig = msgSig;

    if (AddNonceAdmin(msg)) {
        RelayNonceAdmin(msg);
    } else {
        return "ERROR: could not create nonce pair";
    }

    return msg.ToString();
}

UniValue chainadminsign(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "chainadminsign\n"
            "\nCreate a partial signature using the received nonces.\n"
            "\nArguments:\n"
            "1. chain data hash      (string, required) The hash of the chain data to be signed\n"
            "\nExample:\n"
            "\nCreate a partial signature for the hash\n"
            + HelpExampleCli("chainadminlogin", "9afdc03617091ac720958a47dee67fea38c40396594996531564c445f2c7603a")
        );

    LOCK(cs_main);
    UniValue result(UniValue::VOBJ);

    uint256 hashToSign = ParseHashV(params[0], "parameter 1");

    bool fFasito = strMethod == "fasito";

    CAdminPartialSignatureUnsinged signature;
    if (!AdminSignPartial(hashToSign, signature, nChainAdminId, fFasito ? NULL : &adminPrivNonce, nAdminNonceHandle)) {
        string err = strprintf("%s : could not create sig by 0x%08x, hash %s\n", __func__,
                nChainAdminId, hashToSign.ToString());
        result.push_back(Pair("status", err));
        return result;
    }

    CAdminPartialSignature msg(signature);

    CSchnorrSig msgSig;
    if (!AdminSignHash(msg.GetHash(), msgSig, fFasito)) {
        string err = strprintf("%s : could not sign signature message\n", __func__);
        result.push_back(Pair("status", err));
        return result;
    }

    msg.msgSig = msgSig;

    if (AddAdminSignature(msg)) {
        RelayAdminSignature(msg);
    } else {
        result.push_back(Pair("status", "ERROR: could not create partial admin signature"));
        return result;
    }

    result.push_back(Pair("status", "OK"));
    result.push_back(Pair("adminId", strprintf("0x%08x", msg.nAdminId)));
    result.push_back(Pair("hashRootBlock", msg.hashRootBlock.ToString()));
    result.push_back(Pair("hashChainData", msg.hashChainData.ToString()));
    result.push_back(Pair("creationTime", (int64_t)msg.nCreationTime));
    result.push_back(Pair("signerIds", CreateSignerIdList(msg.vSignerIds)));
    result.push_back(Pair("signature", msg.signature.ToString()));

    return result;
}

UniValue addcvn(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "addcvn \"type\" \"node Id\" \"pubkey\"\n"
            "\nAdd a new CVN or admin to the FairCoin network\n"
            "\nArguments:\n"
            "1. \"type\"               (string, required) c=CVNInfo, a=ChainAdmin\n"
            "2. \"Id\"                 (string, required) The ID (in hex) of the new CVN or admin.\n"
            "3. \"pubkey\"             (string, required but can be empty) The public key of the new CVN or Chain Admin (in hex).\n"
            "\nResult:\n"
            "{\n"
                "  \"type\":\"type of added info\",             (string) The type of the added info (c=CVNInfo, a=ChainAdmin)\n"
                "  \"Id\":\"ID in hex\",                        (hex) The ID of the new CVN (or admin) in hexadecimal form\n"
                "  \"prevBlockHash\":\"hash (hex)\",            (string) The timestamp of the block\n"
                "  \"address\":\"faircoin address\",            (string) The FairCoin address of the new CVN.\n"
                "  \"pubKey\":\"public key\",                   (string) The public key of the new CVN (in hex).\n"
                "  \"signatures\":\"number of signatures\"      (string) The number of admin signatures that signed the CvnInfo.\n"
                "  \"chainParams\":\"serialized params\"        (string) The serialized representation of CDynamicChainParams.\n"
             "}\n"
            "\nExamples:\n"
            "\nAdd a new CVN\n"
            + HelpExampleCli("addcvn", "c 0x12348899 \"042288e3...eafe\"")
        );

    LOCK(cs_main);
    UniValue result(UniValue::VOBJ);
    bool fAddCvn = true;
    if (params[0].get_str() == "a")
        fAddCvn = false;

    uint32_t nNodeId;
    stringstream ss;
    ss << hex << params[1].get_str();
    ss >> nNodeId;

    vector<unsigned char> vPubKey = ParseHex(params[2].get_str());

    if (vPubKey.size() != 65)
        throw runtime_error(" Invalid public key: " + params[2].get_str());

    CSchnorrPubKey pubKey;
    CChainDataMsg msg;
    msg.hashPrevBlock = chainActive.Tip()->GetBlockHash();

    if (vPubKey.size() == 65) {
        pubKey = CSchnorrPubKeyDER(params[2].get_str());
        if (fAddCvn)
            AddCvnInfoToMsg(msg, nNodeId, chainActive.Tip()->nHeight + 1, pubKey);
        else
            AddChainAdminToMsg(msg, nNodeId, chainActive.Tip()->nHeight + 1, pubKey);
    }

    if (!AddAdminIds(msg)) {
        return "could not add admin ids";
    }

    // if no or not all signatures are available we print out the CChainDataMsg's hash to sign
    if (mapAdminSigs.empty()) {
        return msg.GetHash().ToString();
    } else {
        CAdminPartialSignature sig = mapAdminSigs.begin()->second;
        if (sig.vSignerIds.size() != mapAdminSigs.size()) {
            return msg.GetHash().ToString();
        }
    }

    if (!AddAdminSignatures(msg))
        return "error in signatures";

    result.push_back(Pair("nodeId", strprintf("0x%08x", nNodeId)));

    if (msg.HasCvnInfo()) {
        CKeyID keyID = CKeyID(pubKey.GetHash160());
        CBitcoinAddress address;
        address.Set(keyID);

        LogPrintf("about to add CVN 0x%08x with pubKey %s (%s) to the network\n", nNodeId, pubKey.ToString(), address.ToString());
        result.push_back(Pair("pubKey", pubKey.ToString()));
        result.push_back(Pair("address", address.ToString()));
    }

    if (msg.HasChainAdmins()) {
        LogPrintf("about to add chain admin 0x%08x with pubKey %s to the network\n", nNodeId, HexStr(vPubKey));
        result.push_back(Pair("pubKey", HexStr(vPubKey)));
    }

    if (IsInitialBlockDownload())
        return "wait for block chain download to finish";

    if (AddChainData(msg)) {
        RelayChainData(msg);
    } else {
        LogPrintf("ERROR\n%s\n", msg.ToString());
    }

    return result;
}

UniValue removecvn(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "removecvn \"type\" \"Id\"\n"
            "\nRemove a CVN or and admin from the FairCoin network\n"
            "\nArguments:\n"
            "1. \"type\"         (string, required) c=CVNInfo, a=ChainAdmin\n"
            "2. \"Id\"           (string, required) The ID (in hex) of the CVN or admin to remove.\n"
            "\nResult:\n"
            "{\n"
                "  \"type\":\"type of info\",                   (string) The type of the info (c=CVNInfo, a=ChainAdmin)\n"
                "  \"Id\":\"node ID (hex)\",                    (string) The ID of the CVN to remove in hexadecimal form\n"
             "}\n"
            "\nExamples:\n"
            "\nRemove a CVN\n"
            + HelpExampleCli("removecvn", "c 0x12348899")
        );

    if (IsInitialBlockDownload())
        return "wait for block chain download to finish";

    LOCK(cs_main);

    bool fRemoveCvn = true;
    if (params[0].get_str() == "a")
        fRemoveCvn = false;

    uint32_t nNodeId;
    stringstream ss;
    ss << hex << params[1].get_str();
    ss >> nNodeId;

    CChainDataMsg msg;
    msg.nPayload      |= (fRemoveCvn ? CChainDataMsg::CVN_PAYLOAD : CChainDataMsg::CHAIN_ADMINS_PAYLOAD);
    msg.hashPrevBlock  = chainActive.Tip()->GetBlockHash();

    if (msg.HasCvnInfo()) {
        LOCK(cs_mapCVNs);
        msg.vCvns.resize(mapCVNs.size() - 1);

        if (!mapCVNs.count(nNodeId))
            throw runtime_error("CVN ID not found");

        uint32_t index = 0;
        BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
        {
            if (cvn.first != nNodeId)
                msg.vCvns[index++] = cvn.second;
        }
    } else {
        LOCK(cs_mapChainAdmins);
        msg.vChainAdmins.resize(mapChainAdmins.size() - 1);

        if (!mapChainAdmins.count(nNodeId))
            throw runtime_error("Admin ID not found");

        uint32_t index = 0;
        BOOST_FOREACH(const ChainAdminMapType::value_type& adm, mapChainAdmins)
        {
            if (adm.first != nNodeId)
                msg.vChainAdmins[index++] = adm.second;
        }
    }

    if (!AddAdminIds(msg)) {
        return "could not add admin ids";
    }

    // if no or not all signatures are available we print out the CChainDataMsg's hash to sign
    if (mapAdminSigs.empty()) {
        return msg.GetHash().ToString();
    } else {
        CAdminPartialSignature sig = mapAdminSigs.begin()->second;
        if (sig.vSignerIds.size() != mapAdminSigs.size()) {
            return msg.GetHash().ToString();
        }
    }

    if (!AddAdminSignatures(msg))
        return "error in signatures";

    LogPrintf("about remove %s 0x%08x from the network\n", fRemoveCvn ? "CVN" : "Admin", nNodeId);

    if (AddChainData(msg)) {
        RelayChainData(msg);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("Id", strprintf("0x%08x", nNodeId)));

    return result;
}

UniValue signchaindata(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "signchaindata \"signchaindata\"\n"
            "\nCreates a signature of chain data\n"
            "\nArguments:\n"
            "1. \"hashChainData\"   (string, required) The hash of the chain data.\n"
            "2. \"PIN\"             (string, optional) The PIN for the fasito private admin key\n"
            "\nExamples:\n"
            "\nCreate a signature\n"
            + HelpExampleCli("signchaindata", "a1b5..9093 123456")
        );

    LOCK(cs_main);

    if (!nChainAdminId || !adminPrivKey.IsValid())
        return "ERROR: wallet not configured for chain administration";

    uint256 hashChainData = uint256S(params[0].get_str());

    CSchnorrSig signature;

    if (params.size() == 2)  {
        // TODO: do fasito stuff
    } else {
        if (!adminPrivKey.SchnorrSign(hashChainData, signature))
            return "error, could not create signature";
    }

    uint32_t dummy[1] = {0};

    UniValue result(UniValue::VOBJ);
    UniValue adminSigners(UniValue::VARR);
    BOOST_FOREACH(const uint32_t& signerId, dummy)
    {
        adminSigners.push_back(strprintf("0x%08x", signerId));
    }
    result.push_back(Pair("signature", signature.ToString()));
    result.push_back(Pair("adminSignerIds", adminSigners));

    return result;
}

UniValue getcvninfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getcvninfo\n"
            "\nDisplay the current state of the CVN\n"
            "\nArguments:\n"
            "1. \"cvnId\"   (string, optional) The ID (in hex) of the CVN to display infos about\n"
            "\nResult:\n"
            "{\n"
                "  \"nextBlockToCreate\":height     ,           (int) The estimated next block to create\n"
                "  \"reserved\":\"reserved\",                   (string) reserved\n"
            "}\n"
            "\nExamples:\n"
            "\nDisplay CVN state\n"
            + HelpExampleCli("getcvninfo", "0x12345678")
        );

    uint32_t nNodeId = nCvnNodeId;

    if (params.size() == 1) {
        stringstream ss;
        ss << hex << params[1].get_str();
        ss >> nNodeId;
    }

    return "to be implemented";
}

UniValue bancvn(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "bancvn\n"
            "\nBan a malicious CVN\n"
            "\nArguments:\n"
            "1. \"cvnId\"   (string, optional) The ID (in hex) of the CVN to ban\n"
            "\nResult:\n"
            "OK   : the CVN was successfully banned\n"
            "ERROR: the supplied CVN ID was unknown\n"
            "\nExamples:\n"
            "\nBan CVN\n"
            + HelpExampleCli("bancvn", "0x12345678")
        );

    uint32_t nNodeId;

    if (params.size() == 1) {
        stringstream ss;
        ss << hex << params[1].get_str();
        ss >> nNodeId;
    }

    if (!mapCVNs.count(nNodeId))
        return "ERROR";

    mapBannedCVNs[nNodeId] = chainActive.Tip()->nHeight;

    return "OK";
}

UniValue getactivecvns(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getactivecvns\n"
            "\nDisplay a list of all currently active CVN\n"
            "\nArguments: none\n"
            "\nResult:\n"
            "{\n"
            "  \"count\" : \"n\",                (numeric) The number currently activated CNVs\n"
            "  \"currentHeight\" : \"n\",        (numberc) The current block height the result relates to\n"
            "  \"cvns\" : [                    (array of json objects)\n"
            "     {\n"
            "       \"nodeId\": \"id\",          (string) The transaction id\n"
            "       \"pubKey\": \"public key\",  (string) The public key of the CVN\n"
            "       \"heightAdded\": n,        (numeric) The height when the CVN was added to the network\n"
            "       \"predictedNextBlock\": n, (numeric) The height of the next block this CVNs most probably will create\n"
            "       \"lastBlocksSigned\": n    (numeric) The number of blocks signed within the last " + strprintf("%d", (int)dynParams.nMinSuccessiveSignatures) + " blocks\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"
            "\nExamples:\n"
            "\nDisplay CVN list\n"
            + HelpExampleCli("getactivecvns","")
        );

    LOCK(cs_mapCVNs);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("count", (int)mapCVNs.size()));
    result.push_back(Pair("currentHeight", chainActive.Tip()->nHeight));
    UniValue cvns(UniValue::VARR);

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
    {
        const CCvnInfo& c = cvn.second;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("nodeId", strprintf("0x%08x", c.nNodeId)));
        entry.push_back(Pair("pubKey", c.pubKey.ToString()));
        entry.push_back(Pair("heightAdded", (int)c.nHeightAdded));

        CCvnStatus status(c.nNodeId);
        CheckNextBlockCreator(chainActive.Tip(), GetAdjustedTime(), &status);
        entry.push_back(Pair("predictedNextBlock", (int)status.nPredictedNextBlock));
        entry.push_back(Pair("lastBlocksSigned", (int)status.nBlockSigned));

        cvns.push_back(entry);
    }

    result.push_back(Pair("cvns", cvns));

    return result;
}

UniValue getactiveadmins(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getactiveadmins\n"
            "\nDisplay a list of all currently active chain administrators\n"
            "\nArguments: none\n"
            "\nResult:\n"
            "{\n"
            "  \"count\" : \"n\",               (numeric) The number currently activated CNVs\n"
            "  \"currentHeight\" : \"n\",       (numberc) The current block height the result relates to\n"
            "  \"admins\" : [                 (array of json objects)\n"
            "     {\n"
            "       \"adminId\": \"id\",        (string) The transaction id\n"
            "       \"pubKey\": \"public key\", (string) The public key of the CVN\n"
            "       \"heightAdded\": n        (numeric) The height when the CVN was added to the network\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"
            "\nExamples:\n"
            "\nDisplay Chain Admins list\n"
            + HelpExampleCli("getactiveadmins","")
        );

    LOCK(cs_mapChainAdmins);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("count", (int)mapChainAdmins.size()));
    result.push_back(Pair("currentHeight", chainActive.Tip()->nHeight));
    UniValue admins(UniValue::VARR);

    BOOST_FOREACH(const ChainAdminMapType::value_type& admin, mapChainAdmins)
    {
        const CChainAdmin& a = admin.second;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("adminId", strprintf("0x%08x", a.nAdminId)));
        entry.push_back(Pair("pubKey", a.pubKey.ToString()));
        entry.push_back(Pair("heightAdded", (int)a.nHeightAdded));

        string strCurrentNonce = "";
        if (mapAdminNonces.count(a.nAdminId)) {
            strCurrentNonce = mapAdminNonces[a.nAdminId].ToString();
        }

        entry.push_back(Pair("currentNonce", strCurrentNonce));

        string strCurrentPartialSig = "";
        if (mapAdminSigs.count(a.nAdminId)) {
            strCurrentPartialSig = mapAdminSigs[a.nAdminId].signature.ToString();
        }

        entry.push_back(Pair("currentPartialSig", strCurrentPartialSig));

        admins.push_back(entry);
    }

    result.push_back(Pair("admins", admins));

    return result;
}

void DynamicChainparametersToJSON(CDynamicChainParams& cp, UniValue& result)
{
    result.push_back(Pair("version", (int)cp.nVersion));
    result.push_back(Pair("minAdminSigs", (int)cp.nMinAdminSigs));
    result.push_back(Pair("maxAdminSigs", (int)cp.nMaxAdminSigs));
    result.push_back(Pair("blockSpacing", (int)cp.nBlockSpacing));
    result.push_back(Pair("blockSpacingGracePeriod", (int)cp.nBlockSpacingGracePeriod));
    result.push_back(Pair("transactionFee", ValueFromAmount(cp.nTransactionFee)));
    result.push_back(Pair("dustThreshold", ValueFromAmount(cp.nDustThreshold)));
    result.push_back(Pair("minSuccessiveSignatures", (int)cp.nMinSuccessiveSignatures));
    result.push_back(Pair("blocksToConsiderForSigCheck", (int)cp.nBlocksToConsiderForSigCheck));
    result.push_back(Pair("percentageOfSignaturesMean", (int)cp.nPercentageOfSignaturesMean));
    result.push_back(Pair("maxBlockSize", (int)cp.nMaxBlockSize));
    result.push_back(Pair("blockPropagationWaitTime", (int)cp.nBlockPropagationWaitTime));
    result.push_back(Pair("retryNewSigSetInterval", (int)cp.nRetryNewSigSetInterval));
    result.push_back(Pair("description", cp.strDescription));
}

UniValue setchainparameters(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setchainparameters {\"nParam1\":123,\"nParam2\":456} [\"n:sigs\",...]\n"
            "\nSet new dynamic chain parameters for FairCoin network\n"
            "\nArguments:\n"
            "1. \"{\"key\":\"val\"}]\" (string, required) The dynamic chain parameters to set\n"
            "\nResult:\n"
            "{\n"
                "  \"prevBlockHash\":\"hash (hex)\",            (string) The timestamp of the block\n"
                "  \"chainParams\":\"serialized params\"        (string) The serialized representation of CDynamicChainParams.\n"
             "}\n"
            "\nExamples:\n"
            "\nSet chain parameters\n"
            + HelpExampleCli("setchainparameters", "\"{\\\"blockSpacing\\\":\\\"180\\\",\\\"blockSpacingGracePeriod\\\":\\\"60\\\"}")
        );

    if (IsInitialBlockDownload())
        return "wait for block chain download to finish";

    LOCK(cs_main);

    CChainDataMsg msg;
    msg.hashPrevBlock = chainActive.Tip()->GetBlockHash();

    if (!AddDynParamsToMsg(msg, params[0].get_obj()))
        return "Invalid parameter detected";

    if (!AddAdminIds(msg)) {
        return "could not add admin ids";
    }

    // if no or not all signatures are available we print out the CChainDataMsg's hash to sign
    if (mapAdminSigs.empty()) {
        LogPrintf("no sigs\n");
        return msg.GetHash().ToString();
    } else {
        CAdminPartialSignature sig = mapAdminSigs.begin()->second;
        if (sig.vSignerIds.size() != mapAdminSigs.size()) {
            LogPrintf("not enough sigs: %u:%u\n", sig.vSignerIds.size(), mapAdminSigs.size());
            return msg.GetHash().ToString();
        }
    }

    UniValue result(UniValue::VOBJ);
    if (!AddAdminSignatures(msg))
        return "error in signatures";

    LogPrintf("about to update dynamic chain parameters on the network\n   %s\n", msg.dynamicChainParams.ToString());
    result.push_back(Pair("hashToSign", msg.GetHash().ToString()));
    result.push_back(Pair("hashPrevBlock", msg.hashPrevBlock.ToString()));
    result.push_back(Pair("dynamicChainParams", msg.dynamicChainParams.ToString()));

    if (AddChainData(msg)) {
        RelayChainData(msg);
    } else {
        LogPrintf("ERROR\n%s\n", msg.ToString());
        return "could not add chain data, see error log";
    }

    return result;
}

UniValue getchainparameters(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getchainparameters\n"
            "\nDisplay the current values of the dynamic chain parameters\n"
            "\nArguments:\n"
            "none\n"
            "\nResult:\n"
            "{\n"
                "  \"nextBlockToCreate\":height     ,           (int) The estimated next block to create\n"
                "  \"reserved\":\"reserved\",                   (string) reserved\n"
             "}\n"
            "\nExamples:\n"
            "\nDisplay dynamic chain parameters\n"
            + HelpExampleCli("getchainparameters","")
        );

    UniValue result(UniValue::VOBJ);
    DynamicChainparametersToJSON(dynParams, result);

    return result;
}

UniValue relaynoncepool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "relaynoncepool true|false\n"
            "\nRelay local nonce pool(s)\n"
            "\nArguments:\n"
            "1. \"sendAll\" (bool, optional) Whether to send all available pools or only the locally created pool (default: true)\n"
            "2. \"verbose\" (bool, optional) Whether to log all the contents of the nonce pools (default: false)\n"
            "\nResult:\n"
            "OK\n"
            "\nExamples:\n"
            "\nSet chain parameters\n"
            + HelpExampleCli("relaynoncepool", "true")
        );

    LOCK(cs_mapNoncePool);
    CBlockIndex *tip = chainActive.Tip();
    const bool fSendAll = params.size() == 1 ? (params[0].get_bool()) : true;
    const bool fVerbose = params.size() == 2 ? (params[1].get_bool()) : false;

    BOOST_FOREACH(const CNoncePoolType::value_type &p, mapNoncePool) {
        const CNoncePool& msg = p.second;
        if (GetPoolAge(msg, tip) < 0) {
            LogPrintf("%s : not sending expired nonce pool from height %d of CVN 0x%08x\n", __func__, msg.nHeightAdded, msg.nCvnId);
            continue;
        }
        if (fSendAll || msg.nCvnId == nCvnNodeId) {
            LogPrintf("relaying nonce pool: %s", msg.ToString(fVerbose));
            RelayNoncePool(msg);
        }
    }

    return "OK";
}

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {};

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    };
};

UniValue submitblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit new block to network.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"    (string, required) the hex-encoded block data to submit\n"
            "2. \"jsonparametersobject\"     (string, optional) object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
            "    }\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );

    CBlock block;
    if (!DecodeHexBlk(block, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                return "duplicate";
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return "duplicate-invalid";
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    CValidationState state;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(state, Params(), NULL, &block, true, NULL);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (fAccepted)
    {
        if (!sc.found)
            return "inconclusive";
        state = sc.state;
    }
    return BIP22ValidationResult(state);
}

#ifdef ENABLE_COINSUPPLY
UniValue addcoinsupply(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "addcoinsupply \"faircoinaddress\" \"amount\"  \"comment\" \"admin sigs\"\n"
            "\nAdd instructions to increase the coin supply to the FairCoin network\n"
            "\nArguments:\n"
            "1. \"faircoinaddress\"  (string, required) The FairCoin address to send to.\n"
            "2. \"amount\"           (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"          (string, required) A comment used to store what this additional supply is for. \n"
            "\nResult:\n"
            "{\n"
                "  \"type\":\"type of added info\",             (string) The type of the added info (c=CVNInfo, a=ChainAdmin)\n"
                "  \"Id\":\"ID in hex\",                        (hex) The ID of the new CVN (or admin) in hexadecimal form\n"
                "  \"prevBlockHash\":\"hash (hex)\",            (string) The timestamp of the block\n"
                "  \"address\":\"faircoin address\",            (string) The FairCoin address of the new CVN.\n"
                "  \"pubKey\":\"public key\",                   (string) The public key of the new CVN (in hex).\n"
                "  \"signatures\":\"number of signatures\"      (string) The number of admin signatures that signed the CvnInfo.\n"
                "  \"chainParams\":\"serialized params\"        (string) The serialized representation of CDynamicChainParams.\n"
             "}\n"
            "\nExamples:\n"
            "\nAdd a new coin supply\n"
            + HelpExampleCli("addcoinsupply", "fairVs8iHyLzgHQrdxb9j6hR4WGpdDbKN3 4000.777 \"thewaterproject.org\"")
        );

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_IN_WARMUP, "wait for block chain download to finish");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid FairCoin address");

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");

    if (params[2].isNull() || params[2].get_str().empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "The comment is mandatory");

    CChainDataMsg msg;
    CCoinSupply& spl = msg.coinSupply;

    msg.nPayload             = CChainDataMsg::COIN_SUPPLY_PAYLOAD;
    msg.hashPrevBlock        = chainActive.Tip()->GetBlockHash();
    spl.nValue               = nAmount;
    spl.scriptDestination    = GetScriptForDestination(address.Get());

    UniValue result(UniValue::VOBJ);

    if (!AddAdminIds(msg)) {
        return "could not add admin ids";
    }

    // if no or not all signatures are available we print out the CChainDataMsg's hash to sign
    if (mapAdminSigs.empty()) {
        return msg.GetHash().ToString();
    } else {
        CAdminPartialSignature sig = mapAdminSigs.begin()->second;
        if (sig.vSignerIds.size() != mapAdminSigs.size()) {
            return msg.GetHash().ToString();
        }
    }

    if (!AddAdminSignatures(msg))
        return "error in signatures";

    if (AddChainData(msg))
        RelayChainData(msg);
    else
        LogPrintf("ERROR\n%s\n", msg.ToString());

    result.push_back(Pair("msghash", msg.GetHash().ToString()));
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("amount", ValueFromAmount(nAmount)));
    result.push_back(Pair("comment", msg.strComment));
    result.push_back(Pair("script", ScriptToAsmStr(msg.coinSupply.scriptDestination, true)));
    return result;
}
#endif

UniValue estimatefee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "estimatefee nblocks\n"
            "\nReturns the current mandatory fee per kilobyte needed for a transaction to be accepted.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required) - dummy value for API compatibility\n"
            "\nResult:\n"
            "n              (numeric) mandatory fee-per-kilobyte\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("estimatefee", "123")
            );

    return ValueFromAmount(dynParams.nTransactionFee);
}
