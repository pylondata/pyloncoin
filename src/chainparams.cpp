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

#define GENESIS_BLOCK_TIMESTAMP 1540824171
const char* genesisMessage = "The first blockchain-based energy trade platform, powered by renewable energy";

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
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0xcf;
        pchMessageStart[3] = 0xfc;
        vAlertPubKey = ParseHex("049F3692B03712571CB09F02E15991EB23249C07818BFB3B325B14A94384B46104C8F7FD2BBA4018FD01D3E2AF284EA292347F5E36946707E9C999A3175CDF6C47");
        nDefaultPort = 40404;
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 20; // 20 seg.
        dynParams.nBlockSpacingGracePeriod     = 20;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 0 * CENT; // 0 PLN per Kb
        dynParams.nDustThreshold               = 0 * CENT; // 0 PLN
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 21000000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 18; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 5; // 15 sec.
        dynParams.nCoinbaseMaturity            = 90; // 90 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://pylon-network.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04d5fb9294aaeddbcab57c2e16053e446ea326f67d689ba86691930919b2bc6f6b9efc762c108360cd7dcec5ad617eefa107ce0572836baf50e6fbe2395acd397f"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("044e765cf675ee70130f904259714e31e631f7c0a311f4642b86febb762d847c24de9f70f79d75402a518e8aa5622149e5a4b258bcc9415573deba008d1819be38"));

        genesis.chainMultiSig = CSchnorrSigS("f71652d6a5a688297b4002d1ea14cf371e6887a74c5edba3f3378c5cfb1ec8e708fe659ee728815fb9164349f7f1452ea502a6b20c562682697e337cb229e36e");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("2626b5c423ac2744fc2fe30a71e37280a89f7f492c8b85a699ceb826bd5d04ba99162af3cb3c9a39e43d1d47387ba9a28e726fbf4e4436ff3d8f1427ea1aa9e5");
        genesis.creatorSignature = CSchnorrSigS("c4962d47e72d229fabf6deb5b13a31f3744a392b5a57f20235f7b84f2a567b3baaeff5a5f1e413689a0252c75481eddc4ee0ad97360d083f31d16892bc5d7ef1");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("5d4cabff4afd8e325c2a81021df441756ea18c72704a20c2858045c9c50d3d9d"));
        assert(genesis.hashMerkleRoot == uint256S("f3d5bd47f1db4b40516d76fa91b1707096a2e4c749e67819cee1001a45fadea3"));
        assert(genesis.hashPayload == uint256S("7bba5c806bcbc6fc0b0edb959886ee099afeb6ddfd90609ae8beea321200e94f"));
#endif
        // vSeeds.push_back(CDNSSeedData("1.pylon-network.org", "pyloncoin2-seed1.pylon-network.org")); // Thomas König
        // vSeeds.push_back(CDNSSeedData("2.pylon-network.org", "pyloncoin2-seed2.pylon-network.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,55);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,53);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
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
        vAlertPubKey = ParseHex("049F3692B03712571CB09F02E15991EB23249C07818BFB3B325B14A94384B46104C8F7FD2BBA4018FD01D3E2AF284EA292347F5E36946707E9C999A3175CDF6C47");
        nDefaultPort = 41404;
        nPruneAfterHeight = 1000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 2 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 45;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 PLN per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 PLN
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 50; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 15; // 15 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://pylon-network.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 1, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04d5fb9294aaeddbcab57c2e16053e446ea326f67d689ba86691930919b2bc6f6b9efc762c108360cd7dcec5ad617eefa107ce0572836baf50e6fbe2395acd397f"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("044e765cf675ee70130f904259714e31e631f7c0a311f4642b86febb762d847c24de9f70f79d75402a518e8aa5622149e5a4b258bcc9415573deba008d1819be38"));

        genesis.chainMultiSig = CSchnorrSigS("8e004c690c375c23851a9751d4c9867c2c0cc4fceba0dbbcedc15814a43bc47f19e007b3c5f164e14921f50ca52cfc1d39c32f42fef356338b761dd7ca724721");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("e06c3bfc7f9d564b556328e2c69c275d853d9765d5f7f417152a1f9526d3a3599ed7b92c11c1e7ebcf3a5ad8b9799151a6a9b9c8998d95fd61b18782c6501791");
        genesis.creatorSignature = CSchnorrSigS("0e0ecbaf45571b4916d5c3909da8cb88f8f9f3c2a934b3156e6eb004a1821b66ce41c6606b9dea88812dbb5e36b9e6382e5d9c3d507881f242bc721bf000d64f");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("a93d193535b5c2894b22ea749157a3e96dc2fdf2e84cb84fcc1e1b0812982fef"));
        assert(genesis.hashMerkleRoot == uint256S("f3d5bd47f1db4b40516d76fa91b1707096a2e4c749e67819cee1001a45fadea3"));
        assert(genesis.hashPayload == uint256S("401fe1f626855ab274ec1c5d3a7ce2caadebf333fcf2b15dba13904acf9063f9"));
#endif
        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("seed1.pylon.network", "seed1-testnet.pylon.network"));
        vSeeds.push_back(CDNSSeedData("seed2.pylon.network", "seed2-testnet.pylon.network"));
        vSeeds.push_back(CDNSSeedData("seed3.pylon.network", "seed3-testnet.pylon.network"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,87);
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
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 PLN per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 PLN
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 20; // 20 sec.
        dynParams.nRetryNewSigSetInterval      = 7; // 7 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://pylon-network.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 2, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04d5fb9294aaeddbcab57c2e16053e446ea326f67d689ba86691930919b2bc6f6b9efc762c108360cd7dcec5ad617eefa107ce0572836baf50e6fbe2395acd397f"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("044e765cf675ee70130f904259714e31e631f7c0a311f4642b86febb762d847c24de9f70f79d75402a518e8aa5622149e5a4b258bcc9415573deba008d1819be38"));

        genesis.chainMultiSig = CSchnorrSigS("8e004c690c375c23851a9751d4c9867c2c0cc4fceba0dbbcedc15814a43bc47f19e007b3c5f164e14921f50ca52cfc1d39c32f42fef356338b761dd7ca724721");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("e06c3bfc7f9d564b556328e2c69c275d853d9765d5f7f417152a1f9526d3a3599ed7b92c11c1e7ebcf3a5ad8b9799151a6a9b9c8998d95fd61b18782c6501791");
        genesis.creatorSignature = CSchnorrSigS("0e0ecbaf45571b4916d5c3909da8cb88f8f9f3c2a934b3156e6eb004a1821b66ce41c6606b9dea88812dbb5e36b9e6382e5d9c3d507881f242bc721bf000d64f");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("92818b2961f06d68d4b99e9a080bd6eb98b88ee96a9ecdfbb502257979107ba6"));
        assert(genesis.hashMerkleRoot == uint256S("f3d5bd47f1db4b40516d76fa91b1707096a2e4c749e67819cee1001a45fadea3"));
        assert(genesis.hashPayload == uint256S("874b877db57e8bc9e0097aa4bce93534bb45ee1e74ce301da39af17d214de2cf"));
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

bool CheckDynamicChainParameters(const CDynamicChainParams& params)
{
    if (params.nBlockSpacing > MAX_BLOCK_SPACING || params.nBlockSpacing < MIN_BLOCK_SPACING) {
        LogPrintf("%s : block spacing %u exceeds limit\n",__func__ , params.nBlockSpacing);
        return false;
    }

    if (params.nTransactionFee > MAX_TX_FEE_THRESHOLD || params.nTransactionFee < MIN_TX_FEE_THRESHOLD) {
        LogPrintf("%s : tx fee threshold %u exceeds limit\n",__func__ , params.nTransactionFee);
        return false;
    }

    if (params.nDustThreshold > MAX_DUST_THRESHOLD || params.nDustThreshold < MIN_DUST_THRESHOLD) {
        LogPrintf("%s : dust threshold %u exceeds limit\n",__func__ , params.nDustThreshold);
        return false;
    }

    if (!params.nMinAdminSigs || params.nMinAdminSigs > params.nMaxAdminSigs) {
        LogPrintf("%s : number of CVN signers %u/%u exceeds limit\n",__func__ , params.nMinAdminSigs, params.nMaxAdminSigs);
        return false;
    }

    if (params.nBlocksToConsiderForSigCheck < MIN_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK || params.nBlocksToConsiderForSigCheck > MAX_BLOCKS_TO_CONSIDER_FOR_SIG_CHECK) {
        LogPrintf("%s : %u blocksToConsiderForSigCheck is out of bounds\n",__func__ , params.nBlocksToConsiderForSigCheck);
        return false;
    }

    if (params.nPercentageOfSignaturesMean < MIN_PERCENTAGE_OF_SIGNATURES_MEAN || params.nPercentageOfSignaturesMean > MAX_PERCENTAGE_OF_SIGNATURES_MEAN) {
        LogPrintf("%s : %u nPercentageOfSignatureMean is out of bounds\n",__func__ , params.nPercentageOfSignaturesMean);
        return false;
    }

    if (params.nMaxBlockSize < MIN_SIZE_OF_BLOCK || params.nMaxBlockSize > MAX_SIZE_OF_BLOCK) {
        LogPrintf("%s : %u nMaxBlockSize is out of bounds\n",__func__ , params.nMaxBlockSize);
        return false;
    }

    if (params.nBlockPropagationWaitTime < MIN_BLOCK_PROPAGATION_WAIT_TIME || params.nBlockPropagationWaitTime > MAX_BLOCK_PROPAGATION_WAIT_TIME ||
            params.nBlockPropagationWaitTime >= params.nBlockSpacing) {
        LogPrintf("%s : %u nBlockPropagationWaitTime is out of bounds\n",__func__ , params.nBlockPropagationWaitTime);
        return false;
    }

    if (params.nRetryNewSigSetInterval < MIN_RETRY_NEW_SIG_SET_INTERVAL || params.nRetryNewSigSetInterval > MAX_RETRY_NEW_SIG_SET_INTERVAL) {
        LogPrintf("%s : %u nRetryNewSigSetInterval is out of bounds\n",__func__ , params.nRetryNewSigSetInterval);
        return false;
    }

    if (params.nCoinbaseMaturity < MIN_COINBASE_MATURITY || params.nCoinbaseMaturity > MAX_COINBASE_MATURITY) {
        LogPrintf("%s : %u nCoinbaseMaturity is out of bounds\n",__func__ , params.nCoinbaseMaturity);
        return false;
    }

    if (params.strDescription.length() <= MIN_CHAIN_DATA_DESCRIPTION_LEN) {
        LogPrintf("%s : chain data description is too short: %s\n",__func__ , params.strDescription);
        return false;
    }

    return true;
}
