// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POC_H
#define BITCOIN_POC_H

#include "consensus/params.h"
#include "primitives/block.h"
#include "chainparams.h"
#include "chain.h"
#include "sync.h"

#include <stdint.h>
#include <boost/unordered_set.hpp>

#define GENESIS_NODE_ID  0xc001d00d
#define GENESIS_ADMIN_ID 0xad3aee01

typedef std::map<uint32_t, CCvnInfo> CvnMapType;
typedef std::map<uint32_t, CChainAdmin> ChainAdminMapType;

typedef std::map<uint32_t, CCvnPartialSignature> CvnSigSignerType;
typedef std::map<uint32_t, CvnSigSignerType> CvnSigCreatorType;
typedef std::map<uint256, CvnSigCreatorType> CvnSigMapType;

typedef std::map<uint32_t, CCvnPubNonceMsg> CvnNonceSignerType;
typedef std::map<uint32_t, CvnNonceSignerType> CvnNonceCreatorType;
typedef std::map<uint256, CvnNonceCreatorType> CvnNonceMapType;

typedef std::map<uint256, CChainDataMsg> ChainDataMapType;

typedef boost::unordered_set<uint32_t> TimeWeightSetType;
typedef std::vector<uint32_t>::reverse_iterator CandidateIterator;
typedef map<uint256, const CBlockIndex *> BlockIndexByPrevHashType;
typedef map<uint32_t, uint32_t> BannedCVNMapType; // nCreatorID/nHeight at which it has been banned

/** dynamic chain parameters range checks */
#define MAX_BLOCK_SPACING 3600
#define MIN_BLOCK_SPACING 30
#define MAX_DUST_THRESHOLD 1 * COIN
#define MIN_DUST_THRESHOLD 0
#define MAX_TX_FEE_THRESHOLD 1 * COIN
#define MIN_TX_FEE_THRESHOLD 0
#define MIN_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK 1
#define MAX_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK 100
#define MIN_PERCENTAGE_OF_SIGNATURES_MEAN 33
#define MAX_PERCENTAGE_OF_SIGNATURES_MEAN 100
#define MIN_SIZE_OF_BLOCK 100000
#define MAX_SIZE_OF_BLOCK 5000000

#define __DBG_ LogPrintf("DEBUG: In file %s in function %s in line %d\n", __FILE__, __func__, __LINE__);

extern CCriticalSection cs_mapCVNs;
extern CvnMapType mapCVNs;
extern CCriticalSection cs_mapChainAdmins;
extern ChainAdminMapType mapChainAdmins;
extern CCriticalSection cs_mapCvnNonces;
extern CvnNonceMapType mapCvnNonces;
extern CCriticalSection cs_mapCvnSigs;
extern CvnSigMapType mapCvnSigs;
extern CCriticalSection cs_mapChainData;
extern ChainDataMapType mapChainData;
extern CCriticalSection cs_mapBlockIndexByPrevHash;
extern BlockIndexByPrevHashType mapBlockIndexByPrevHash;
extern CCriticalSection cs_mapBannedCVNs;
extern BannedCVNMapType mapBannedCVNs;

extern bool CvnSignHash(const uint256 &hashToSign, CSchnorrSig& signature);
extern bool CvnSignPartial(const uint256 &hashPrevBlock, CCvnPartialSignature& signature, const uint32_t& nNextCreator, const uint32_t& nNodeId);
extern int CombinePartialSignatures(CSchnorrSig& allsig, uint8_t *sigs[], int nSignatures);
extern bool CvnSignBlock(CBlock& block);
extern bool CvnVerifyChainSignature(const CBlockHeader& block);
extern bool CvnVerifySignature(const uint256 &hash, const CSchnorrSig &sig, const CSchnorrPubKey &pubKey);
extern bool CvnVerifySignature(const uint256 &hash, const CSchnorrSig &sig, const uint32_t nCvnId);
extern bool CvnVerifyAdminSignature(const vector<uint32_t> &nAdminIds, const uint256 &hashAdmin, const CSchnorrSig &sig);
extern bool CheckForDuplicateCvns(const CBlock& block);
extern bool CheckForDuplicateChainAdmins(const CBlock& block);
extern void SendCVNSignature(const CBlockIndex *pindexNew);
extern bool AddCvnSignature(const CCvnPartialSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId);
extern bool AddChainData(const CChainDataMsg& msg);
extern void RemoveCvnSigsAndNonces(const uint256& hashPrevBlock);
extern bool CvnVerifyPartialSignature(const CCvnPartialSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId);
extern bool CheckAdminSignature(const vector<uint32_t> &vAdminIds, const uint256 &hashAdmin, const CSchnorrSig &sig, const bool fCoinSupply);
extern void RelayChainData(const CChainDataMsg& msg);
extern void RelayCvnSignature(const CCvnPartialSignatureMsg& msg);

extern bool AddCvnPubNonce(const CCvnPubNonceMsg& msg);
extern void SendCVNNonce(const CBlockIndex *pindexNew);
extern void RelayCvnPubNonce(const CCvnPubNonceMsg& msg);
extern void RemoveCvnPubNonces(const uint256& hashPrevBlock);

extern uint32_t CheckNextBlockCreator(const CBlockIndex* pindexStart, const int64_t nTimeToTest, CCvnStatus* state = NULL);

/** Check whether a block hash satisfies the proof-of-cooperation requirements */
extern bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params&);

extern void UpdateCvnInfo(const CBlock* pblock);
extern void UpdateChainParameters(const CBlock* pblock);
extern void UpdateChainAdmins(const CBlock* pblock);

extern bool CheckDynamicChainParameters(const CDynamicChainParams& params);

extern void POC_create_secp256k1_context();
extern void POC_destroy_secp256k1_context();

/** strart the CVN voter thread */
extern void RunCVNSignerThread(const bool fGenerate, const CChainParams& chainparams, const uint32_t& nNodeId);

#endif // BITCOIN_POC_H
