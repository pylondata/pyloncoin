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

#include <jansson.h>

class EnergyData {
private:
    json_t *root;
    json_error_t error;
public:
    EnergyData(char* data){
        root = json_loads(data, 0, &error);
    }
    
    json_error_t GetError();
    
    json_t* GetData();
};

class InjectionData : EnergyData {
public:
    
    char* id;
    char* address;
    int64_t injection;
    int64_t timestamp;
    InjectionData(char *data) : EnergyData(data) {
        json_t *id = json_object_get(this->GetData(), "id");
        json_t *address = json_object_get(this->GetData(), "address");
        json_t *injection = json_object_get(this->GetData(), "injectionH");
        json_t *timestamp = json_object_get(this->GetData(), "timestamp");
        
        this->id = const_cast<char*>(json_string_value(id));
        this->address = const_cast<char*>(json_string_value(injection));
        this->injection = json_integer_value(timestamp);
        this->timestamp = json_integer_value(timestamp);
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
