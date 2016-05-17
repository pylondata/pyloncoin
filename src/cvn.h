// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CVN_H
#define BITCOIN_CVN_H

#include <openssl/ssl.h>

class CKey;

extern uint32_t nCvnNodeId;
extern CKey cvnPrivKey;
extern CPubKey cvnPubKey;

X509* InitCVNWithCertificate();
uint32_t SetupCVN(X509 *x509Cert);

#endif // BITCOIN_CVN_H
