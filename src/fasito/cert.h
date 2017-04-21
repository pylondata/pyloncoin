// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FAIRCOIN_CVN_H
#define FAIRCOIN_CVN_H

#include "key.h"

extern CKey cvnPrivKey;
extern CSchnorrPubKey cvnPubKey;
extern CKey adminPrivKey;
extern CSchnorrPubKey adminPubKey;

extern uint32_t InitCVNWithCertificate(const string &strFasitoPassword);
extern uint32_t InitChainAdminWithCertificate(const string& strPassword);

#endif // FAIRCOIN_CVN_H
