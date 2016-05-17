// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "clientversion.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "rpcserver.h"
#include "timedata.h"
#include "util.h"
#include "utilstrencodings.h"
#include "tinyformat.h"
#include "poc.h"
#include "consensus/validation.h"
#include "consensus/merkle.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

#include <stdint.h>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string.hpp>
#include <univalue.h>
#include <iostream>
#include <string>

using namespace std;

/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total bitcoin balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolversion", PROTOCOL_VERSION));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
        obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
    }
#endif
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("timeoffset",    GetTimeOffset()));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string())));
    obj.push_back(Pair("testnet",       Params().TestnetToBeDeprecatedFieldRPC()));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    }
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
#endif
    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (pwalletMain && pwalletMain->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        if (pwalletMain && pwalletMain->GetCScript(scriptID, subscript)) {
            vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            UniValue a(UniValue::VARR);
            BOOST_FOREACH(const CTxDestination& addr, addresses)
                a.push_back(CBitcoinAddress(addr).ToString());
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }
};
#endif

UniValue validateaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress \"bitcoinaddress\"\n"
            "\nReturn information about the given bitcoin address.\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"     (string, required) The bitcoin address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"bitcoinaddress\", (string) The bitcoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

#ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", (mine & ISMINE_SPENDABLE) ? true : false));
        ret.push_back(Pair("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
        ret.pushKVs(detail);
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest].name));
#endif
    }
    return ret;
}

/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(const UniValue& params)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const string& ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: Bitcoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (pwalletMain && address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
        if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
                strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE));

    return result;
}

UniValue createmultisig(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
    {
        string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are bitcoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"key\"    (string) bitcoin address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);
    CBitcoinAddress address(innerID);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

UniValue verifymessage(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage \"bitcoinaddress\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}

UniValue setmocktime(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw runtime_error("setmocktime for regression testing (-regtest mode) only");

    // cs_vNodes is locked and node send/receive times are updated
    // atomically with the time change to prevent peers from being
    // disconnected because we think we haven't communicated with them
    // in a long time.
    LOCK2(cs_main, cs_vNodes);

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));
    SetMockTime(params[0].get_int64());

    uint64_t t = GetTime();
    BOOST_FOREACH(CNode* pnode, vNodes) {
        pnode->nLastSend = pnode->nLastRecv = t;
    }

    return NullUniValue;
}

static bool AddAdminSignatures(CChainDataMsg &msg, const UniValue& sigs)
{
    if (sigs.size() < (size_t)dynParams.nMinCvnSigners)
        throw runtime_error(
            strprintf("not enough signatures supplied "
                      "(got %u signatures, but need at least %u to sign)", sigs.size(), (size_t)dynParams.nMinCvnSigners));
    if (sigs.size() > (size_t)dynParams.nMaxCvnSigners)
        throw runtime_error(
            strprintf("too many signatures supplied %u (%u max)\nReduce the number", sigs.size(), (size_t)dynParams.nMaxCvnSigners));

    msg.vAdminSignatures.resize(sigs.size());

    for (uint32_t i = 0 ; i < sigs.size() ; i++)
    {
        const string& strSig = sigs[i].get_str();
        vector<string> vTokens;
        boost::split(vTokens, strSig, boost::is_any_of(":"));

        if (vTokens.size() != 2)
            throw runtime_error(strprintf("signature %u is of invalid format", i + 1));

        uint32_t signerId;
        stringstream ss;
        ss << hex << vTokens[0].c_str();
        ss >> signerId;

        msg.vAdminSignatures[i] = CCvnSignature(signerId, ParseHex(vTokens[1]));
    }

    return CheckAdminSignatures(msg.GetHash(), msg.vAdminSignatures);
}

static void AddCvnInfoToMsg(CChainDataMsg &msg, const uint32_t nNodeId, const uint32_t nHeightAdded, const vector<unsigned char> vPubKey)
{
    msg.nPayload |= CChainDataMsg::CVN_PAYLOAD;
    msg.vCvns.resize(mapCVNs.size() + 1);

    uint32_t index = 0;
    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs)
    {
        msg.vCvns[index++] = cvn.second;
    };

    CCvnInfo cvn(nNodeId, nHeightAdded, vPubKey);
    msg.vCvns[index] = cvn;
}

static void AddChainAdminToMsg(CChainDataMsg &msg, const uint32_t nAdminId, const vector<unsigned char> vPubKey)
{
    msg.nPayload |= CChainDataMsg::CHAIN_ADMINS_PAYLOAD;
    msg.vChainAdmins.resize(mapChainAdmins.size() + 1);

    uint32_t index = 0;
    BOOST_FOREACH(const ChainAdminMapType::value_type& cvn, mapChainAdmins)
    {
        msg.vChainAdmins[index++] = cvn.second;
    };

    CChainAdmin admin(nAdminId, vPubKey);
    msg.vChainAdmins[index] = admin;
}

static void AddDynParamsToMsg(CChainDataMsg& msg, UniValue jsonParams)
{
    LogPrintf("AddDynParamsToBlock : adding %u parameters\n", jsonParams.getKeys().size());
    msg.nPayload |= CChainDataMsg::CHAIN_PARAMETERS_PAYLOAD;

    CDynamicChainParams& params = msg.dynamicChainParams;

    params.nBlockSpacing            = dynParams.nBlockSpacing;
    params.nBlockSpacingGracePeriod = dynParams.nBlockSpacingGracePeriod;
    params.nDustThreshold           = dynParams.nDustThreshold;
    params.nMaxCvnSigners           = dynParams.nMaxCvnSigners;
    params.nMinCvnSigners           = dynParams.nMinCvnSigners;
    params.nMinSuccessiveSignatures = dynParams.nMinSuccessiveSignatures;

    vector<string> paramsList = jsonParams.getKeys();
    BOOST_FOREACH(const string& key, paramsList) {
        LogPrintf("AddDynParamsToBlock : adding %s: %u\n", key, jsonParams[key].get_int());
        if (key == "nBlockSpacing") {
            params.nBlockSpacing = jsonParams[key].get_int();
        } else if (key == "nBlockSpacingGracePeriod") {
            params.nBlockSpacingGracePeriod = jsonParams[key].get_int();
        } else if (key == "nDustThreshold") {
            params.nDustThreshold = jsonParams[key].get_int();
        } else if (key == "nMaxCvnSigners") {
            params.nMaxCvnSigners = jsonParams[key].get_int();
        } else if (key == "nMinCvnSigners") {
            params.nMinCvnSigners = jsonParams[key].get_int();
        } else if (key == "nMinSuccessiveSignatures") {
            params.nMinSuccessiveSignatures = jsonParams[key].get_int();
        }
    }
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
            "4. \"[n:sigs]\"           (string, required) The admin signatures prefix by the signer ID (n)\n"
            "5. \"{\"key\":\"val\"}]\" (string, optional) The dynamic chain parameters to set)\n"
            "\nResult:\n"
            "{\n"
                "  \"type\":\"type of added info\",             (string) The type of the added info (c=CVNInfo, a=ChainAdmin)\n"
                "  \"Id\":\"ID in hex\",                    (hex) The ID of the new CVN (or admin) in hexadecimal form\n"
                "  \"prevBlockHash\":\"hash (hex)\",            (string) The timestamp of the block\n"
                "  \"address\":\"faircoin address\",            (string) The FairCoin address of the new CVN.\n"
                "  \"pubKey\":\"public key\",                   (string) The public key of the new CVN (in hex).\n"
                "  \"signatures\":\"number of signatures\"      (string) The number of admin signatures that signed the CvnInfo.\n"
                "  \"chainParams\":\"serialized params\"        (string) The serialized representation of CDynamicChainParams.\n"
             "}\n"
            "\nExamples:\n"
            "\nAdd a new CVN\n"
            + HelpExampleCli("addcvn", "c 0x123488 1461056246 \"04...00\" [\\\"0x87654321:a1b5..9093\\\",\\\"0xdeadcafe:0432..12aa\\\"] \"{\\\"nParapm1\\\":\\\"123\\\",\\\"nParapm2\\\":\\\"456\\\"}")
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
    CPubKey pubKey(vPubKey);

    if (!pubKey.IsFullyValid() && params[4].isNull())
        throw runtime_error(" Invalid public key: " + params[2].get_str());

    const UniValue& sigs = params[3].get_array();

    CChainDataMsg msg;
    msg.hashPrevBlock = chainActive.Tip()->GetBlockHash();

    if (pubKey.IsFullyValid()) {
        if (fAddCvn)
            AddCvnInfoToMsg(msg, nNodeId, chainActive.Tip()->nHeight + 1, vPubKey);
        else
            AddChainAdminToMsg(msg, nNodeId, vPubKey);
    }

    if (params[4].isObject() && !params[4].get_obj().getKeys().empty())
        AddDynParamsToMsg(msg, params[4].get_obj());

    // if no signatures are supplied we print out the CChainDataMsg's hash to sign
    if (!sigs.size())
        return msg.GetHash().ToString();

    if (!AddAdminSignatures(msg, sigs))
        return "error in signatures";

    result.push_back(Pair("nodeId", strprintf("0x%08x", nNodeId)));

    if (msg.HasCvnInfo()) {
        CKeyID keyID = pubKey.GetID();
        CBitcoinAddress address;
        address.Set(keyID);

        LogPrintf("about to add CVN 0x%08x with pubKey %s (%s) to the network\n", nNodeId, HexStr(vPubKey), address.ToString());
        result.push_back(Pair("pubKey", HexStr(vPubKey)));
        result.push_back(Pair("address", address.ToString()));
    }

    if (msg.HasChainParameters()) {
        LogPrintf("about to update dynamic chain parameters on the network\n   %s\n", msg.dynamicChainParams.ToString());
        result.push_back(Pair("dynamicChainParams", msg.dynamicChainParams.ToString()));
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
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "removecvn \"Id\" \"timestamp\" [\"n:sigs\",...]\n"
            "\nRemove a CVN from the FairCoin network\n"
            "\nArguments:\n"
            "1. \"type\"         (string, required) c=CVNInfo, a=ChainAdmin\n"
            "2. \"Id\"           (string, required) The ID (in hex) of the CVN or admin to remove.\n"
            "3. \"n:sigs\"       (string, required) The admin signatures prefix by the signer ID (n)\n"
            "\nResult:\n"
            "{\n"
                "  \"type\":\"type of info\",                   (string) The type of the info (c=CVNInfo, a=ChainAdmin)\n"
                "  \"Id\":\"node ID (hex)\",                    (string) The ID  of the new CVN in hex separated by a space\n"
             "}\n"
            "\nExamples:\n"
            "\nRemove a CVN\n"
            + HelpExampleCli("removecvn", "c 0x123488 [\"0x87654321:a1b5..9093\",\"0x3453:0432..12aa\"]")
        );

    LOCK(cs_main);

    bool fRemoveCvn = true;
    if (params[0].get_str() == "a")
        fRemoveCvn = false;

    uint32_t nNodeId;
    stringstream ss;
    ss << hex << params[1].get_str();
    ss >> nNodeId;

    const UniValue& sigs = params[2].get_array();

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
        };
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
        };
    }

    if (IsInitialBlockDownload())
        return "wait for block chain download to finish";

    // if no signatures are supplied we print out the CChainDataMsg's hash to sign
    if (!sigs.size())
        return msg.GetHash().ToString();

    AddAdminSignatures(msg, sigs);
    LogPrintf("about remove %s 0x%08x from the network\n", fRemoveCvn ? "CVN" : "Admin", nNodeId);;

    if (AddChainData(msg)) {
        RelayChainData(msg);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("Id", strprintf("0x%08x", nNodeId)));

    return result;
}

UniValue signchaindata(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "signchaindata \"signchaindata\"\n"
            "\nCreates a signature of chain data\n"
            "\nArguments:\n"
            "1. \"hashChainData\"   (string, required) The hash of the chain data.\n"
            "2. \"adminId\"         (string, required) The admin ID (hex)\n"
            "3. \"privKey\"         (string, required) The private key of the chain admin\n"
            "\nExamples:\n"
            "\nCreate a signature\n"
            + HelpExampleCli("signchaindata", "a1b5..9093")
        );

    LOCK(cs_main);

    uint256 hashChainData = uint256S(params[0].get_str());

    uint32_t nAdminId;
    stringstream ss;
    ss << hex << params[1].get_str();
    ss >> nAdminId;

    vector<unsigned char> vSignature;

    CBitcoinSecret secret;
    if (!secret.SetString(params[2].get_str()))
        return "private key is invalid";

    CKey key = secret.GetKey();
    if (!key.Sign(hashChainData, vSignature))
        return "CvnSignWithKey : could not create block signature";

    CCvnSignature sig(nAdminId, vSignature);

    if (!CvnVerifyAdminSignature(hashChainData, sig)) {
        return "error signing chain data";
    }

    return "\"" + params[1].get_str() + ":" + HexStr(vSignature) + "\"";
}
