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

#include <univalue.h>

using namespace std;

class EnergyData {
private:
    UniValue root;
public:
    EnergyData(char* data);
    
    UniValue GetData();
};

class InjectionData : EnergyData {
public:
    
    char* id;
    char* address;
    int64_t injection;
    int64_t timestamp;
    InjectionData(char *data);
    
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
