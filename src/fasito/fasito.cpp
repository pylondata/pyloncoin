// Copyright (c) 2017 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "primitives/block.h"
#include "poc.h"
#include "cvn.h"

#include <secp256k1.h>
#include <openssl/ssl.h>

bool fFasitoUnlocked = false;

//#define FASITO_DEBUG 0

bool CreateNonceWithFasito(const uint256& hashUnsignedBlock, const CKey cvnPrivKey, unsigned char *pPrivateData, CSchnorrNonce& noncePublic, const CCvnInfo& cvnInfo)
{
    return false;
}

bool CvnSignWithFasito(const uint256& hashUnsignedBlock, CCvnPartialSignatureUnsinged& signature, const CCvnInfo& cvnInfo)
{

#ifdef FASITO_DEBUG
    LogPrintf("CvnSignWithFasito : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), signature.nSignerId,
            cvnInfo.pubKey.ToString(),
            signature.signature.ToString());
#endif
    return true;
}

uint32_t InitCVNWithFasito()
{
    return NULL;
}

uint32_t InitChainAdminWithFasito()
{
    return NULL;
}
