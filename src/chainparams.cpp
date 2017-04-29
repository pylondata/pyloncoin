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

#if SHOW_GENESIS_HASHES
#define PRINT_HASHES \
    printf("%s parameters\n" \
            "block hash   : %s\n" \
            "merkle root  : %s\n" \
            "payload hash : %s\n\n", \
            strNetworkID.c_str(), \
            consensus.hashGenesisBlock.ToString().c_str(), \
            genesis.hashMerkleRoot.ToString().c_str(), \
            genesis.hashPayload.ToString().c_str())
#endif

#define GENESIS_BLOCK_TIMESTAMP 1493456000
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
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 3 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 60;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 50; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 15; // 15 sec.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("0495b3d6338fc20b93b28220782a7444f8061d7794c4ba906dc38ea4041298d74e47b4a3544470ee7e6e8872321b853ba98bd1c32ccff30eb8da6475605082bcf0"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("23b0abfd31729436474a1e46662fa9c8fd76a7bb35ff1788beb2af1b5dc879de9aedf0c7f11757e23803d7b7b0ebdb1712f22b942dd13241dc9e16360aba0760");
        genesis.creatorSignature = CSchnorrSigS("dc0781af888849fe24caa8c1e510f311cdcbb1d097fe1aadf2bed98e49a790a9f909201ec7bcf9e78612d820fd8448fac12854dc761282844fb219662edee972");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("50631d09b850ebeb9fd6e6b047d5fb3063498651297272639ebf57b594c5d336"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        assert(genesis.hashPayload == uint256S("1171a49db36313d2ee7ef8684a152a75f8913fb6b653bf42124046898d8b2713"));
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
 * Testnet
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
        nPruneAfterHeight = 1000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 2 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 45;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 50; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 15; // 15 sec.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 1, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("0495b3d6338fc20b93b28220782a7444f8061d7794c4ba906dc38ea4041298d74e47b4a3544470ee7e6e8872321b853ba98bd1c32ccff30eb8da6475605082bcf0"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("aae1f9defe51c90404fef404c140d3b87bef708693e861d6d125f54a8ab3022d771344bc52419f93c69027afcb7c2134d080928c8afc9e5e0dc2f34c423025c6");
        genesis.creatorSignature = CSchnorrSigS("bbe18aea45eb5b2cb2f091655ddda6d6d439e6648ed1d50017f03254b4518279d8a30bf3d0be24513b0099d0c0b48d95086ffd382819b1364e1f821a83c74b97");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("9eaf9d5e1b4c9e2b1f9908009f46394ce6ef9cae6ed0522a710cdc40b44e2b17"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        assert(genesis.hashPayload == uint256S("332ef9fee6186c31d30599c832ed14820c584d843e962f60399c20e75690725f"));
#endif
        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-testnet-seed1.fair-coin.org")); // Thomas König

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
        nDefaultPort = 42404;
        nPruneAfterHeight = 1000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 1 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 30;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 20; // 20 sec.
        dynParams.nRetryNewSigSetInterval      = 7; // 7 sec.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 2, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("0495b3d6338fc20b93b28220782a7444f8061d7794c4ba906dc38ea4041298d74e47b4a3544470ee7e6e8872321b853ba98bd1c32ccff30eb8da6475605082bcf0"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("5bfe4673f0dbe5d617e94cde778e8c6ccb7334afd69a40a218821152c51632ea4e69c22db0da14e8e67a58aa35c8a1e8a8102b028f2d97cdcd13b1c29e89c7bd");
        genesis.creatorSignature = CSchnorrSigS("5b7f44528074f9409419aefb8b0248753086a9ee9616a8968127dedf5c7efbac5a08c1fd5f7dddabcecb891eced9819b3e756c6ebad8239ed2d4c11c314763dd");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("073eb284b7c87ae162360bdd2032f4e1715579b7fc46c7e9c7b3f88491688efa"));
        assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        assert(genesis.hashPayload == uint256S("3203d7470c41079cc9cc2ad2129dc008dfcdeb6ce11ba9536af6646c4249abce"));
#endif
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fCreateBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

#if 0
        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("fac71114e0630bb4c8722144ea843fcc8b465ac77820e86251d37141bd3da26e")),
            1461766275,
            0,
            0
        };
#endif
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
