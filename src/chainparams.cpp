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
        nMaxTipAge = 60 * 60; // 1h
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing            = 3 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod = 60;
        dynParams.nMaxAdminSigs            = 11;
        dynParams.nMinAdminSigs            = 3;
        dynParams.nTransactionFee          = 10 * CENT; // 0.1 FAIR
        dynParams.nDustThreshold           = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures = 1;

        genesis = CreateGenesisBlock(1465223123, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, ParseHex("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(3);
        genesis.vChainAdmins[0] = CChainAdmin(0xad000001, ParseHex("04a1fe3aee6cd4b05d06cd7c686cf45a7820a9e28adb090e6576e8885f1013a829e1bbee64001b22d54825932e7602a04adf1e2511f765c6ab9792482b58063494"));
        genesis.vChainAdmins[1] = CChainAdmin(0xad000002, ParseHex("045420bd35ada00cee9a194eb4cde20ff6f18b55235ac3ce5cbccbbbe97caa00d610c19d5006bf4193fe45e2c5a380f6a490972bedbda7d875de83478604eb0043"));
        genesis.vChainAdmins[2] = CChainAdmin(0xad000003, ParseHex("044bf8939429e9f53b8b8f8b5bd07bc72b056bc58414eb319c050a4d7ab4a8de0053a694a1f35e80db4c480f5de25ca8e1a0d5b289138f055b04945e73e964c417"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CCvnSignature genesisSignature(GENESIS_NODE_ID, ParseHex("3045022100c2a6c1348eb68a035a5f265aa0eb9037de2423e155505bbf6982e88500e64fad0220378ca2f87186fabff68f224856a672cf19af2328baf2c826019be5baad934215"));
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        genesis.vAdminSignatures.resize(3);
        genesis.vAdminSignatures[0] = CCvnSignature(0xad000001, ParseHex("304402203a4c2b4ac0954cb9c74d67ebba0107091d157ff46ec5679eaf0cee965f7121070220744ba3c2b0c98d169989614252175fa9b22744604b0f3bd44e3f8d4ed6b41255"));
        genesis.vAdminSignatures[1] = CCvnSignature(0xad000002, ParseHex("3045022100928001a317cd04d5decb4addddc55fb4066fd2d4d8031142515b5c4e392de2c1022025e948167362c2a0189329891689dddd567d319b860dd43982129d7e19ebe2ac"));
        genesis.vAdminSignatures[2] = CCvnSignature(0xad000003, ParseHex("304402205145317ec801ef3f1d0b061c5536b5848d16897c7da4f4ae95fa502ddcfea36002204d1596bd79a6b4f148d74645875e99b7c9d582bba06cba690e169f2b21410127"));

        genesis.vCreatorSignature = ParseHex("3044022060323217db4be4727d54feb6c2dac14c0556c76bad471e5f8cdd55750c53ab1e022053830d519423adb2053443e1ca1b67307e98297d9c665821771db32ff8b42dd3");

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("4fdcc972f4463dac159eac45de78da9b45e476de4f6408cd141d041df3b616b3"));
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
        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        vAlertPubKey = ParseHex("045894f38e9dd72b6f210c261d40003eb087030c42b102d3b238b396256d02f5a380ff3b7444d306d9e118fa1fc7b2b7594875f4eb64bbeaa31577391d85eb5a8a");
        nDefaultPort = 41404;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;
        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing            = 2 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod = 45;
        dynParams.nMaxAdminSigs            = 11;
        dynParams.nMinAdminSigs            = 1;
        dynParams.nTransactionFee          = 10 * CENT; // 0.1 FAIR
        dynParams.nDustThreshold           = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures = 1;

        genesis = CreateGenesisBlock(1465223123, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, ParseHex("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(3);
        genesis.vChainAdmins[0] = CChainAdmin(0xad000001, ParseHex("04a1fe3aee6cd4b05d06cd7c686cf45a7820a9e28adb090e6576e8885f1013a829e1bbee64001b22d54825932e7602a04adf1e2511f765c6ab9792482b58063494"));
        genesis.vChainAdmins[1] = CChainAdmin(0xad000002, ParseHex("045420bd35ada00cee9a194eb4cde20ff6f18b55235ac3ce5cbccbbbe97caa00d610c19d5006bf4193fe45e2c5a380f6a490972bedbda7d875de83478604eb0043"));
        genesis.vChainAdmins[2] = CChainAdmin(0xad000003, ParseHex("044bf8939429e9f53b8b8f8b5bd07bc72b056bc58414eb319c050a4d7ab4a8de0053a694a1f35e80db4c480f5de25ca8e1a0d5b289138f055b04945e73e964c417"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CCvnSignature genesisSignature(GENESIS_NODE_ID, ParseHex("3045022100c2a6c1348eb68a035a5f265aa0eb9037de2423e155505bbf6982e88500e64fad0220378ca2f87186fabff68f224856a672cf19af2328baf2c826019be5baad934215"));
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        genesis.vAdminSignatures.resize(3);
        genesis.vAdminSignatures[0] = CCvnSignature(0xad000001, ParseHex("3043021f680a746357ef4e2b36a13711553e3aea6b1d13e36907241eaa435900ecd2a4022067775583c8137b28e33c626b09b57f3c1aeab17138f06348b3df888d539e4f83"));
        genesis.vAdminSignatures[1] = CCvnSignature(0xad000002, ParseHex("304402207d605ca614bea6a66c550c4681677a8c4fe406617b9031dc4921ca9d17576bad02207f2e76010da286f058fcc0d41a796a155c307edc27e32bbcfcd654c004d2b302"));
        genesis.vAdminSignatures[2] = CCvnSignature(0xad000003, ParseHex("304402201509f847f802e622a40c9cb10e33a0daf5df1ee022a856ade400d48761f28ca002204ac81e373bb669e0d6b2d5e828cebe39a12dc099a31382ccecbf4b553d945a4f"));

        genesis.vCreatorSignature = ParseHex("3045022100dfef9f354cc5930dfd9a89af90eaa566b9a137f14881f0e861fe00e2f2bf8afd02202f542a131ab636e19c4c48c65941d57f066977dcca7b1b1e89c1a8c3ccdd7b74");

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("d3b8cd01a123e2e93f4c3a27474f032e921bd6c728458ff73f09bec09a28ae4d"));
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

        genesis = CreateGenesisBlock(1465223123, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, ParseHex("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CCvnSignature genesisSignature(GENESIS_NODE_ID);
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("33565f384cc47515ecd9fcc8e375c128f3262e408df172698379ceceb53b2e41"));
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
