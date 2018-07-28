/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "primitives/txdata.h"

json_error_t EnergyData::GetError() {
    return error;
}
    
json_t* EnergyData::GetData() {
    return root;
}