/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   txdata.h
 * Author: ander
 *
 * Created on 28 de julio de 2018, 12:26
 */

#ifndef TXDATA_H
#define TXDATA_H

#include "serialize.h"
#include <univalue.h>

#include <string>

using namespace std;

class InjectionData {
public:
    int32_t nVersion;
    string id;
    string idfab;
    string timezone;
    int64_t timestamp;
    int64_t consD;    
    int64_t consH;
    int64_t prodD;
    int64_t prodH;
    double ppow;
    string address;
    
    InjectionData(std::string& data);
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nVersion);
        READWRITE(id);
        READWRITE(idfab);
        READWRITE(timezone);
        READWRITE(timestamp);
        READWRITE(consD);
        READWRITE(consH);
        READWRITE(prodD);
        READWRITE(prodH);
        READWRITE(ppow);
        READWRITE(address);
    }
    
    bool operator == (const InjectionData &ref) const {
        return ref.id == this->id;
    }
    
    bool operator < (const InjectionData &ref) const {
        return ref.timestamp < this->timestamp;
    }
    
    bool operator > (const InjectionData &ref) const {
        return ref.timestamp > this->timestamp;
    }
    
    bool operator <= (const InjectionData &ref) const {
        return ref.timestamp <= this->timestamp;
    }
    
    bool operator >= (const InjectionData &ref) const {
        return ref.timestamp >= this->timestamp;
    }
};


#endif /* TXDATA_H */
