/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "primitives/txdata.h"
#include "util.h"
#include <univalue.h>

InjectionData::InjectionData(std::string& data) {
    
    UniValue root(UniValue::VOBJ);
    root.read(data);
    
    vector<string> keys = root.getKeys();
    
    for (string key : keys) {
        LogPrintf("InjectionData key=%s\n", key.c_str());
        if (key == "version") {
            this->nVersion = root[key].get_int();
        } else if (key == "id") {
            this->id = root[key].get_str();
        } else if (key == "id-fab") {
            this->idfab = root[key].get_str();
        } else if (key == "address") {
            this->address = root[key].get_str();
        } else if (key == "timezone") {
            this->timezone = root[key].get_str();
        } else if (key == "address") {
            this->address = root[key].get_str();
        } else if (key == "data") {
            UniValue data = root[key].get_obj();
            vector<string> dataKeys = data.getKeys();
            for (string k : dataKeys) {
                if (k == "consD") {
                    this->consD = data[k].get_int64();
                } else if (k == "consH") {
                    this->consH = data[k].get_int64();
                } else if (k == "prodD") {
                    this->prodD = data[k].get_int64();
                } else if (k == "prodH") {
                    this->prodH = data[k].get_int64();
                }else if (k == "ppow") {
                    this->ppow = data[k].get_real();
                }
            }
        } else if (key == "timestamp") {
            this->timestamp = root[key].get_int64();
        }
    }
}