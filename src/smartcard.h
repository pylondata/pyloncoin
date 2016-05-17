// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SMARTCARD_H
#define BITCOIN_SMARTCARD_H

#include "primitives/block.h"

X509* InitCVNWithSmartCard();
bool CvnSignWithSmartCard(const uint256& hashUnsignedBlock, CCvnSignature& signature, const CCvnInfo& cvnInfo);

extern bool fSmartCardUnlocked;

#endif // BITCOIN_SMARTCARD_H
