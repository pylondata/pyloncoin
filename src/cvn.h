// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CVN_H
#define BITCOIN_CVN_H

#include <openssl/ssl.h>

class CKey;

extern uint32_t nCvnNodeId;
extern uint32_t nChainAdminId;

extern CKey cvnPrivKey;
extern CSchnorrPubKey cvnPubKey;
extern CKey adminPrivKey;
extern CSchnorrPubKey adminPubKey;

X509* InitCVNWithCertificate();
X509* InitChainAdminWithCertificate();
uint32_t ExtractIdFromCertificate(X509 *x509Cert, const bool fChainAdmin);

#endif // BITCOIN_CVN_H
