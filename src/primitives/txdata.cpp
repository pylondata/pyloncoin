/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "primitives/txdata.h"
#include <univalue.h>

EnergyData::EnergyData(char* data) {
    root.read(data);
}
    
UniValue EnergyData::GetData() {
    return root;
}

InjectionData::InjectionData(char *data) : EnergyData(data) {
    
    UniValue root = this->GetData();
    std::vector<string> keys = root.getKeys();
    
    for (string key : keys) {
        
        if (key == "id") {
            this->id = const_cast<char*>(root["id"].getValStr().c_str());
        } else if (key == "address") {
            this->address = const_cast<char*>(root["address"].getValStr().c_str());
        } else if (key == "injectionH") {
            this->injection = root["injection"].get_int64();
        } else if (key == "timestamp") {
            this->timestamp = root["timestamp"].get_int64();
        }
    }
}