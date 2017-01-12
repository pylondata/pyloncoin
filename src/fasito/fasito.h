// Copyright (c) 2017 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SMARTCARD_H
#define BITCOIN_SMARTCARD_H

#include "primitives/block.h"

extern uint32_t InitCVNWithFasito();
extern bool CreateNonceWithFasito(const uint256& hashUnsignedBlock, const CKey cvnPrivKey, unsigned char *pPrivateData, CSchnorrNonce& noncePublic, const CCvnInfo& cvnInfo);
extern bool CvnSignWithFasito(const uint256& hashUnsignedBlock, CCvnPartialSignatureUnsinged& signature, const CCvnInfo& cvnInfo);

extern uint32_t InitChainAdminWithFasito();

extern bool fFasitoUnlocked;

#endif // BITCOIN_SMARTCARD_H
