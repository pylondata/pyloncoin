// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "primitives/block.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "key.h"
#include "poc.h"
#include "base58.h"
#include "chainparamsseeds.h"

#include <stdio.h>
#include <assert.h>
#include <boost/assign/list_of.hpp>

CDynamicChainParams dynParams;

#define SHOW_GENESIS_HASHES 0

#define GENESIS_BLOCK_TIMESTAMP 1486481640
const char* genesisMessage = "FairCoin - the currency for a fair economy.";

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nCreatorId, const CDynamicChainParams& dynamicChainParams)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << OP_0 << CScriptNum(GENESIS_NODE_ID) << OP_0; // Serialised block height + genesis node ID + zero
    txNew.vout[0].nValue = 0;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>((uint8_t*)genesisMessage, (uint8_t*)genesisMessage + strlen(genesisMessage));

    CBlock genesis;
    genesis.nVersion   = CBlock::CURRENT_VERSION | CBlock::TX_PAYLOAD | CBlock::CVN_PAYLOAD | CBlock::CHAIN_PARAMETERS_PAYLOAD | CBlock::CHAIN_ADMINS_PAYLOAD;
    genesis.nTime      = nTime;
    genesis.nCreatorId = nCreatorId;
    genesis.hashPrevBlock.SetNull();
    genesis.vtx.push_back(txNew);
    genesis.dynamicChainParams = dynamicChainParams;
    return genesis;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        vAlertPubKey = ParseHex("04b06af4982ca3edc2c040cc2cde05fa5b33264af4a98712ceb29d196e7390b4753eb7264dc5f383f29a44d63e70dbbd8d9e46a0a60f80ef62fd1911291ec388e4");
        nDefaultPort = 40404;
        nMaxTipAge = 30 * 60; // 30 min.
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing            = 3 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod = 60;
        dynParams.nMaxAdminSigs            = 11;
        dynParams.nMinAdminSigs            = 1;
        dynParams.nTransactionFee          = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold           = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean = 70; // 70%
        dynParams.nMaxBlockSize            = 1500000; // 1.5Mb

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("0495b3d6338fc20b93b28220782a7444f8061d7794c4ba906dc38ea4041298d74e47b4a3544470ee7e6e8872321b853ba98bd1c32ccff30eb8da6475605082bcf0"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("2bfb01a9c6b55f1fead12d5db5e604f6730a820501f09f05903eeb86067548fc48515dbecaba0ed8d25b3c2c541ab01bb4ddec3cf0f3803eae307d314cb1f8f6");
        genesis.creatorSignature = CSchnorrSigS("5c450c4924f0a037c45ff4a6abe027306432ff7c652be7ef1dc00e63ec72547b862a8304af56f68c67cd5355e785cdce97d2472649347f7890c6fef2da5fa263");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("1f701f2b8de1339dc0ec908f3fb6e9b0b870b6f20ba893e120427e42bbc048d7"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
#endif
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-seed1.fair-coin.org")); // Thomas König
        vSeeds.push_back(CDNSSeedData("2.fair-coin.org", "faircoin2-seed2.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,36);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fCreateBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

#if 0
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("49443ff1f4876f972e130e19c0969794aefd7aeb57ec65cdda386eea22a36cb2")),
            1462293889, // * UNIX timestamp of last checkpoint block
            0,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0     // * estimated number of transactions per day after checkpoint
        };
#endif
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        pchMessageStart[0] = 0x0c;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x0a;
        pchMessageStart[3] = 0x08;
        vAlertPubKey = ParseHex("045894f38e9dd72b6f210c261d40003eb087030c42b102d3b238b396256d02f5a380ff3b7444d306d9e118fa1fc7b2b7594875f4eb64bbeaa31577391d85eb5a8a");
        nDefaultPort = 41404;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;
        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing            = 2 * 60; // 2 min.
        dynParams.nBlockSpacingGracePeriod = 45;
        dynParams.nMaxAdminSigs            = 11;
        dynParams.nMinAdminSigs            = 1;
        dynParams.nTransactionFee          = 10 * CENT; // 0.1 FAIR
        dynParams.nDustThreshold           = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean = 70; // 70%
        dynParams.nMaxBlockSize            = 1500000; // 1.5Mb

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 1, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(0xad000001, 0, CSchnorrPubKeyDER("0495b3d6338fc20b93b28220782a7444f8061d7794c4ba906dc38ea4041298d74e47b4a3544470ee7e6e8872321b853ba98bd1c32ccff30eb8da6475605082bcf0"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("fabd381fb2a735f03666c03c3d0d08c0c1ad1f3350f81c5539765e09046e94a2dc69b534e48942d6ec60eb32494b014bee00660fecf0f08786dc06d7cbb93bd7");
        genesis.creatorSignature = CSchnorrSigS("5642246388ede17058a1b7d870e523c4ceadd43fa0957b04088136fb2c0bf32ef03a49fa285725c5ef0b4df5bac773b049d119e567a2bcaa3c6d757ab134d4ae");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("a721a0ca9f5381d47d02c7d1a9e50c0a54c991c6c3de39f526ad2a148f537c3d"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
#endif
        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-seed1.fair-coin.org")); // Thomas König
        vSeeds.push_back(CDNSSeedData("2.fair-coin.org", "faircoin2-seed2.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fCreateBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

#if 0
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("fac71114e0630bb4c8722144ea843fcc8b465ac77820e86251d37141bd3da26e")),
            1461766275,
            1488,
            300
        };
#endif
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nMaxTipAge = 60 * 60; // 1h
        nDefaultPort = 42404;
        nPruneAfterHeight = 1000;
        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing            = 1 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod = 30;
        dynParams.nMaxAdminSigs            = 11;
        dynParams.nMinAdminSigs            = 1;
        dynParams.nTransactionFee          = 10 * CENT; // 0.1 FAIR
        dynParams.nDustThreshold           = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean = 70; // 70%
        dynParams.nMaxBlockSize            = 1500000; // 1.5Mb

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 2, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyS("f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.chainMultiSig = CSchnorrSigS("a72fe573bb3ab202c7877cee3fab2ec7bbd733032536b6c2b8a0b9a48e61992da6442754414db30d82391224be7d0b596704a1b2baba4de8396ab340dd900b14");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("2980c1d39e75e0757b4288babc4322bb901f9b9962ba7958ebf58ec74e28ea58aca4830fa363ae104c3da1792e2bad170d6c6c6c1814d4d904902a5bbd7e96ff");
        genesis.creatorSignature = CSchnorrSigS("f35033d284b0a4ea164df9428597e801d216ffe64e43909d399388076bd2b5153f9f879e52fc78c38ebef13908387d430553fe71f5bbab5a2b62614f93b20134");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("81a387a07bd46cf6e48de9ad6a42fe3e06b1e43154d5167811ba420afc5a46a1"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
#endif
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fCreateBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("fac71114e0630bb4c8722144ea843fcc8b465ac77820e86251d37141bd3da26e")),
            1461766275,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
