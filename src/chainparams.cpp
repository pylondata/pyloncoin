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

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nCreatorId, const CDynamicChainParams& dynamicChainParams)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << GENESIS_NODE_ID;
    txNew.vout[0].nValue = 0;
    txNew.vout[0].scriptPubKey = CScript() << ParseHex("04e27d35f6f56ab5a1974cc9bd59a9e0a130d5269487a5c061c15ce837e188b8a9f85bab72168c1a1570d5fdffa3c0acc04f4824446919f96be90a007738040c88") << OP_CHECKSIG;

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
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
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
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing = 3 * 60;
        dynParams.nBlockSpacingGracePeriod = 60;
        dynParams.nMaxCvnSigners = 11;
        dynParams.nMinCvnSigners = 3;
        dynParams.nDustThreshold = 10000; // µFAIR
        dynParams.nMinSuccessiveSignatures = 1;

        genesis = CreateGenesisBlock(1463251460, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, ParseHex("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(3);
        genesis.vChainAdmins[0] = CChainAdmin(0xad000001, ParseHex("04a1fe3aee6cd4b05d06cd7c686cf45a7820a9e28adb090e6576e8885f1013a829e1bbee64001b22d54825932e7602a04adf1e2511f765c6ab9792482b58063494"));
        genesis.vChainAdmins[1] = CChainAdmin(0xad000002, ParseHex("045420bd35ada00cee9a194eb4cde20ff6f18b55235ac3ce5cbccbbbe97caa00d610c19d5006bf4193fe45e2c5a380f6a490972bedbda7d875de83478604eb0043"));
        genesis.vChainAdmins[2] = CChainAdmin(0xad000003, ParseHex("044bf8939429e9f53b8b8f8b5bd07bc72b056bc58414eb319c050a4d7ab4a8de0053a694a1f35e80db4c480f5de25ca8e1a0d5b289138f055b04945e73e964c417"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CCvnSignature genesisSignature(GENESIS_NODE_ID, ParseHex("3045022100c2a6c1348eb68a035a5f265aa0eb9037de2423e155505bbf6982e88500e64fad0220378ca2f87186fabff68f224856a672cf19af2328baf2c826019be5baad934215"));
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        genesis.vCreatorSignature = ParseHex("30440220126e7279442bb3db360b4f22eefd22338a99a655c962f4b271a5d4636385e872022015026f9463247043b1c1186c2f94591ce9741feaa05b0b55cb13146e4288b9f3");

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        // also update checkpoints!
        assert(consensus.hashGenesisBlock == uint256S("b47399d14fcb0a8b969cfa02bf461effc21e2f8f273532fb1f119278dd2b00e8"));
        assert(genesis.hashMerkleRoot == uint256S("c8bf1a91c6ae81a4d6d93dc4f44dd49ea93e89776cf7cf2a7b18db66ec040aef"));
#endif
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-seed1.fair-coin.org")); // Thomas König
        vSeeds.push_back(CDNSSeedData("2.fair-coin.org", "faircoin2-seed2.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,36);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = false; //TODO: set to true again
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
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
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        vAlertPubKey = ParseHex("045894f38e9dd72b6f210c261d40003eb087030c42b102d3b238b396256d02f5a380ff3b7444d306d9e118fa1fc7b2b7594875f4eb64bbeaa31577391d85eb5a8a");
        nDefaultPort = 41404;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;
        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing = 2 * 60;
        dynParams.nBlockSpacingGracePeriod = 45;
        dynParams.nMaxCvnSigners = 1;
        dynParams.nMinCvnSigners = 1;
        dynParams.nDustThreshold = 10000; // µFAIR
        dynParams.nMinSuccessiveSignatures = 1;

        genesis = CreateGenesisBlock(1463251461, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, ParseHex("04e27d35f6f56ab5a1974cc9bd59a9e0a130d5269487a5c061c15ce837e188b8a9f85bab72168c1a1570d5fdffa3c0acc04f4824446919f96be90a007738040c88"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CCvnSignature genesisSignature(GENESIS_NODE_ID);
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("b3e9f417d17d7325b95a6553a9e756543f4c3c9e4764607d5120f0412f61cced"));
        assert(genesis.hashMerkleRoot == uint256S("c8bf1a91c6ae81a4d6d93dc4f44dd49ea93e89776cf7cf2a7b18db66ec040aef"));
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

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
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
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nMaxTipAge = 24 * 60 * 60;
        nDefaultPort = 42404;
        nPruneAfterHeight = 1000;
        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing = 1 * 60;
        dynParams.nBlockSpacingGracePeriod = 30;
        dynParams.nMaxCvnSigners = 1;
        dynParams.nMinCvnSigners = 1;
        dynParams.nDustThreshold = 10000; // µFAIR
        dynParams.nMinSuccessiveSignatures = 1;


        genesis = CreateGenesisBlock(1463251462, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, ParseHex("04e27d35f6f56ab5a1974cc9bd59a9e0a130d5269487a5c061c15ce837e188b8a9f85bab72168c1a1570d5fdffa3c0acc04f4824446919f96be90a007738040c88"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CCvnSignature genesisSignature(GENESIS_NODE_ID);
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("0615132cbeea44d1e60025520f444a66549ff8766aae09c56db2c974e504a315"));
        assert(genesis.hashMerkleRoot == uint256S("c8bf1a91c6ae81a4d6d93dc4f44dd49ea93e89776cf7cf2a7b18db66ec040aef"));
#endif
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
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
