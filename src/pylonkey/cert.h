// Copyright (c) 2016 The Faircoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PLNCOIN_CVN_H
#define PLNCOIN_CVN_H

#include "key.h"

extern CKey cvnPrivKey;
extern CSchnorrPubKey cvnPubKey;
extern CKey adminPrivKey;
extern CSchnorrPubKey adminPubKey;

extern uint32_t InitCVNWithCertificate(const string &strPylonkeyPassword);
extern uint32_t InitChainAdminWithCertificate(const string& strPassword, string &strError);

#endif // PLNCOIN_CVN_H
