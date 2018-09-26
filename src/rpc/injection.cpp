/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "rpc/server.h"
#include "net.h"
#include "init.h"
#include "main.h"
#include "poc.h"
#include "base58.h"
#include "wallet/wallet.h"
#include "primitives/txdata.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util.h"

#include <univalue.h>
#include <string>

using namespace std;

static const CAmount MIN_INJECTION_DATA_AMOUNT = 100000;

void InjectionDataToJSON(const InjectionData& iData, UniValue& entry) {
    entry.pushKV("version", iData.nVersion);
    entry.pushKV("id", iData.id);
    entry.pushKV("id-fab", iData.idfab);
    entry.pushKV("timestamp", iData.timestamp);
    entry.pushKV("timezone", iData.timezone);
    entry.pushKV("address", iData.address);
    
    UniValue data(UniValue::VOBJ);
    data.pushKV("consD", iData.consD);
    data.pushKV("consH", iData.consH);
    data.pushKV("prodD", iData.prodD);
    data.pushKV("prodH", iData.prodH);
    
    entry.pushKV("data", data);
}

UniValue sendinjectiondata(const UniValue& params, bool fHelp) {
    
    if (fHelp || params.size() != 1){
        throw runtime_error(
                "sendinjectiondata \"{\"id\": \"identifier\", \"id-fab\": \"vendor id\", \"timezone\": \"XXX/XXX\", \"data\": { ... } }\n"
                "Send a injection data in a transaction\n"
                
                "\nArguments:\n"
                "1. \"data\"            (string, required) The data to be send in JSON format\n"
                
                "\nResult:\n"
                "\"txid\"            TX id where data was sent.\n"
                
                "\nExample:\n"
                "sendinjectiondata \"{'timestamp': '1536177600', 'id-fab': 'ES0021000009887389HP', 'id': 'T+demo+CES0021000009887389HP', 'data': {'consH': 218, 'prodD': 0, 'prodH': 0, 'consD': 3771, 'ppow': 0.0}, 'timezone': 'Europe/Madrid'}\""
                );         
    }
    
    //Build data from json string
    string jsonString = params[0].getValStr();
    InjectionData iData(jsonString);
    
    //Serilization of data
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << iData;
    
    CSerializeData cd;
    ss.GetAndClear(cd);
    
    //Compression
    char* data = cd.data();
    char compressedData[1024 * 1024]; //1 MB
    
    bool compressed = Compress(data, compressedData);
    
    vector<char> dataBuffer;
    
    if (compressed) {
        int size = strlen(compressedData);
        dataBuffer.resize(size);
        
        dataBuffer.insert(dataBuffer.end(), compressedData, compressedData + size);
        dataBuffer.insert(dataBuffer.begin(), 0, 0x01);
    } else {
        int size = strlen(data);
        dataBuffer.resize(size);
        
        dataBuffer.insert(dataBuffer.end(), data, data + size);
        char d[1];
        d[0] = 0x01;
        dataBuffer.insert(dataBuffer.begin(), d, d + 1);
    }
    
    //Create a vector of recipients to send data
    vector<CRecipient> vToSend;
    vToSend.reserve(2);
    
    vector<unsigned char> finalData(dataBuffer.begin(), dataBuffer.end());
    CScript dataScript;
    dataScript << OP_RETURN;
    dataScript << finalData;
    CRecipient dataOut = { dataScript, 0, false};
    vToSend.push_back(dataOut);     
    
    CBitcoinAddress address(iData.address);
    if (!address.IsValid()) {
     throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid PylonCoin address: ")+iData.address);
     }
     
     CScript scriptPubKey = GetScriptForDestination(address.Get());
     
     CRecipient output = { scriptPubKey, MIN_INJECTION_DATA_AMOUNT, false };
     vToSend.push_back(output);
     
     LogPrintf("sendinjectiondata: numOutputs=%d\n", vToSend.size());
     EnsureWalletIsUnlocked();
     
     //Create and sign transaction
     CWalletTx wtx;
     CReserveKey reservekey(pwalletMain);
     CAmount feeRequired;
     string failReason;
     string strError;
     int pos = -1;
     if (!pwalletMain->CreateTransaction(vToSend, wtx, reservekey, feeRequired, pos, failReason, NULL, true, CTransaction::INJECTION_VERSION)) {
     if (MIN_INJECTION_DATA_AMOUNT + feeRequired > pwalletMain->GetBalance())
     strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(feeRequired));
     throw JSONRPCError(RPC_WALLET_ERROR, strError);
     }
     
     //Send Transaction
     
     if (!pwalletMain->CommitTransaction(wtx, reservekey))
     throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
     
     return wtx.GetHash().GetHex();
}