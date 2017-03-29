// Copyright (c) 2016-2017 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockfactory.h>
#include "base58.h"
#include "rpcserver.h"
#include "util.h"
#include "main.h"
#include "utilstrencodings.h"
#include "poc.h"
#include "fasito/cert.h"
#include "core_io.h"
#include "timedata.h"
#include "validationinterface.h"
#include "consensus/validation.h"

#include <boost/algorithm/string.hpp>
#include <univalue.h>

using namespace std;

static bool AddAdminSignatures(CChainDataMsg &msg, const UniValue& adminIds, const UniValue& multiSig)
{
    const uint32_t nSigs = (uint32_t)adminIds.size();
    if (nSigs < dynParams.nMinAdminSigs)
        throw runtime_error(
            strprintf("not enough signatures supplied "
                      "(got %u signatures, but need at least %u to sign)", nSigs, dynParams.nMinAdminSigs));
    if (nSigs > dynParams.nMaxAdminSigs)
        throw runtime_error(
            strprintf("too many signatures supplied %u (%u max)\nReduce the number", nSigs, dynParams.nMaxAdminSigs));

    if (msg.HasCoinSupplyPayload() && nSigs < dynParams.nMaxAdminSigs)
        throw runtime_error(
                strprintf("not enough signatures supplied "
                       "(got %u signatures, but need at least %u to sign for coin supply)", nSigs, dynParams.nMaxAdminSigs));

    msg.adminMultiSig.SetHex(multiSig.get_str());

    for (uint32_t i = 0 ; i < nSigs ; i++)
    {
        uint32_t signerId;
        stringstream ss;
        ss << hex << adminIds[i].get_str().c_str();
        ss >> signerId;

        msg.vAdminIds.push_back(signerId);
    }

    return CheckAdminSignature(msg.vAdminIds, msg.GetHash(), msg.adminMultiSig, msg.HasCoinSupplyPayload());
}

static void AddCvnInfoToMsg(CChainDataMsg &msg, const uint32_t nNodeId, const uint32_t nHeightAdded, const CSchnorrPubKey &pubKey)
{
    msg.nPayload |= CChainDataMsg::CVN_PAYLOAD;
    msg.vCvns.resize(mapCVNs.size() + 1);

    uint32_t index = 0;
    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
    {
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
    BOOST_FOREACH(const ChainAdminMapType::value_type& cvn, mapChainAdmins)
    {
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
        LogPrintf("AddDynParamsToMsg : adding %s: %u\n", key, jsonParams[key].getValStr());
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

    return fAllGood & (params.strDescription.length() > MIN_CHAIN_DATA_DESCRIPTION_LEN);
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

UniValue addcvn(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw runtime_error(
            "addcvn \"type\" \"Id\" \"timestamp\" \"pubkey\" [\"n:sigs\",...] {\"nParam1\":123,\"nParam2\":456}\n"
            "\nAdd a new CVN to the FairCoin network\n"
            "\nArguments:\n"
            "1. \"type\"               (string, required) c=CVNInfo, a=ChainAdmin\n"
            "2. \"Id\"                 (string, required) The ID (in hex) of the new CVN or admin.\n"
            "3. \"pubkey\"             (string, required but can be empty) The public key of the new CVN or Chain Admin (in hex).\n"
            "4. \"[nAdminIds]\"        (string, required) The adminIds that created the multi signature\n"
            "5. \"adminMultiSig\"      (string, required) The combined admin signature\n"
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
            + HelpExampleCli("addcvn", "c 0x123488 1461056246 \"04...00\" [\\\"0x87654321:a1b5..9093\\\",\\\"0xdeadcafe:0432..12aa\\\"]")
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
    const UniValue& adminIds = params[3].get_array();

    CChainDataMsg msg;
    msg.hashPrevBlock = chainActive.Tip()->GetBlockHash();

    if (vPubKey.size() == 65) {
        pubKey = CSchnorrPubKeyDER(params[2].get_str());
        if (fAddCvn)
            AddCvnInfoToMsg(msg, nNodeId, chainActive.Tip()->nHeight + 1, pubKey);
        else
            AddChainAdminToMsg(msg, nNodeId, chainActive.Tip()->nHeight + 1, pubKey);
    }

    // if no signatures are supplied we print out the CChainDataMsg's hash to sign
    if (params[3].isNull() || params[3].empty() || params[4].isNull())
        return msg.GetHash().ToString();

    if (!AddAdminSignatures(msg, adminIds, params[4].get_str()))
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
    } else
         LogPrintf("ERROR\n%s\n", msg.ToString());

    return result;
}

UniValue removecvn(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "removecvn \"Id\" \"timestamp\" [\"n:sigs\",...]\n"
            "\nRemove a CVN from the FairCoin network\n"
            "\nArguments:\n"
            "1. \"type\"         (string, required) c=CVNInfo, a=ChainAdmin\n"
            "2. \"Id\"           (string, required) The ID (in hex) of the CVN or admin to remove.\n"
            "3. \"[adminIds]\"   (array, required) The admin signatures prefixed by the signer ID (n)\n"
            "4. \"adminMultiSig\" (string, required) The admin signatures prefixed by the signer ID (n)\n"
            "\nResult:\n"
            "{\n"
                "  \"type\":\"type of info\",                   (string) The type of the info (c=CVNInfo, a=ChainAdmin)\n"
                "  \"Id\":\"node ID (hex)\",                    (string) The ID of the CVN to remove in hexadecimal form\n"
             "}\n"
            "\nExamples:\n"
            "\nRemove a CVN\n"
            + HelpExampleCli("removecvn", "c 0x123488 [\"0x87654321:a1b5..9093\",\"0x3453:0432..12aa\"]")
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

    const UniValue& adminIds = params[2].get_array();

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

    // if no signatures are supplied we print out the CChainDataMsg's hash to sign
    if (params[3].isNull())
        return msg.GetHash().ToString();

    if (!AddAdminSignatures(msg, adminIds, params[3].get_str()))
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

    if (!mapArgs.count("-admin") || !nChainAdminId || !adminPrivKey.IsValid())
        return "ERROR: wallet not configured for chain administration";

    uint256 hashChainData = uint256S(params[0].get_str());

    /********************************
     * THIS IS ALL WRONG
     * and needs to be implemented and
     * adopted for schnorr k-of-k sigs
     */

    CSchnorrSig signature;

    if (params.size() == 2)  {
        // TODO: do fasito stuff
    } else {
        if (!adminPrivKey.SchnorrSign(hashChainData, signature))
            return "error, could not create signature";
    }

    return signature.ToString();
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
            "\nArguments:\n"
            "\nResult:\n"
            "{\n"
            "  \"nCvns\" : \"n\",               (numeric) The number currently activated CNVs\n"
            "  \"currentHeight\" : \"n\",       (numberc) The current block height the result relates to\n"
            "  \"cvns\" : [                   (array of json objects)\n"
            "     {\n"
            "       \"nodeId\": \"id\",         (string) The transaction id\n"
            "       \"pubKey\": \"public key\", (string) The public key of the CVN\n"
            "       \"heightAdded\": n        (numeric) The height when the CVN was added to the network\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "\nExamples:\n"
            "\nDisplay CVN list\n"
            + HelpExampleCli("getactivecvns","")
        );

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("nCvns", (int)mapCVNs.size()));
    result.push_back(Pair("currentHeight", chainActive.Tip()->nHeight));
    UniValue cvns(UniValue::VARR);

    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
    {
        const CCvnInfo& c = cvn.second;

        UniValue cvnEntry(UniValue::VOBJ);
        cvnEntry.push_back(Pair("nodeId", strprintf("0x%08x", c.nNodeId)));
        cvnEntry.push_back(Pair("pubKey", c.pubKey.ToString()));
        cvnEntry.push_back(Pair("heightAdded", (int)c.nHeightAdded));

        CCvnStatus status(c.nNodeId);
        CheckNextBlockCreator(chainActive.Tip(), GetAdjustedTime(), &status);
        cvnEntry.push_back(Pair("predictedNextBlock", (int)status.nPredictedNextBlock));
        cvnEntry.push_back(Pair("lastBlocksSigned", (int)status.nBlockSigned));

        cvns.push_back(cvnEntry);
    }

    result.push_back(Pair("cvns", cvns));

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
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "setchainparameters {\"nParam1\":123,\"nParam2\":456} [\"n:sigs\",...]\n"
            "\nSet new dynamic chain parameters for FairCoin network\n"
            "\nArguments:\n"
            "1. \"{\"key\":\"val\"}]\" (string, required) The dynamic chain parameters to set\n"
            "2. \"[nAdminIds,...]\"    (string, optional) The adminIds that created the multi signature\n"
            "3. \"adminMultiSig\"      (string, optional) The combined admin signature\n"
            "\nResult:\n"
            "{\n"
                "  \"prevBlockHash\":\"hash (hex)\",            (string) The timestamp of the block\n"
                "  \"chainParams\":\"serialized params\"        (string) The serialized representation of CDynamicChainParams.\n"
             "}\n"
            "\nExamples:\n"
            "\nSet chain parameters\n"
            + HelpExampleCli("setchainparameters", "\"{\\\"blockSpacing\\\":\\\"180\\\",\\\"blockSpacingGracePeriod\\\":\\\"60\\\"} [\"0xadminID01\",\"0xadminId02\"] \"44...55\"")
        );

    if (IsInitialBlockDownload())
        return "wait for block chain download to finish";

    LOCK(cs_main);

    CChainDataMsg msg;
    msg.hashPrevBlock = chainActive.Tip()->GetBlockHash();

    if (!AddDynParamsToMsg(msg, params[0].get_obj()))
        return "invlaid parameter detcted";

    UniValue result(UniValue::VOBJ);
    // if no signatures are supplied we print out the CChainDataMsg's hash to sign
    if (params[1].isNull() || params[2].isNull())
        return msg.GetHash().ToString();

    if (!AddAdminSignatures(msg, params[1].get_array(), params[2].get_str()))
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
    if (fHelp || params.size() != 4)
        throw runtime_error(
            "addcoinsupply \"faircoinaddress\" \"amount\"  \"comment\" \"admin sigs\"\n"
            "\nAdd instructions to increase the coin supply to the FairCoin network\n"
            "\nArguments:\n"
            "1. \"faircoinaddress\"  (string, required) The FairCoin address to send to.\n"
            "2. \"amount\"           (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"          (string, required) A comment used to store what this additional supply is for. \n"
            "4. \"n:sigs\"           (string, required) The admin signatures prefixed by the signer ID (n)\n"
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

    const UniValue& sigs = params[3].get_array();

    CChainDataMsg msg;
    CCoinSupply& spl = msg.coinSupply;

    msg.nPayload             = CChainDataMsg::COIN_SUPPLY_PAYLOAD;
    msg.hashPrevBlock        = chainActive.Tip()->GetBlockHash();
    spl.nValue               = nAmount;
    spl.scriptDestination    = GetScriptForDestination(address.Get());

    UniValue result(UniValue::VOBJ);

    // if no signatures are supplied we print out the CChainDataMsg's hash to sign
    if (sigs.empty())
        return msg.GetHash().ToString();

    if (!AddAdminSignatures(msg, sigs))
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
