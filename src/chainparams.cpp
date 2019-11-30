// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <crypto/equihash.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

// For equihash_parameters_acceptable.
#include <net.h>
#include <validation.h>
#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * >>> from pyblake2 import blake2s
 * >>> 'LitecoinZ' + blake2s(b'NY Times 05/Oct/2011 Steve Jobs, Apple’s Visionary, Dies at 56LTC#433272 27659f4c97de825afe9f1d4ab6c2ba4e83751a11f0144905b0fec849c36fb1ce LTC#741825 27659c79fbb898e9c35f55d49126afcc3a63d1501d399651f21980c538cbaa8f DJIA close on 29 Nov 2017: 23,940.68').hexdigest()
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "LitecoinZ6f099db24212fc48cc80bcf8d46874cd44a7a196625cc1e08a567bff77da2e79";
    const CScript genesisOutputScript = CScript() << ParseHex("04aaa049f7609d4b17ac733a67dd8abd10c0b5b410f0b3681b36dfb85fdc157fa22257895785bfc0c8741a9ff87d98d8a9a5330a8790aadd2f709576f65b37db89") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP16Enabled = true;
        consensus.BIP34Enabled = true;
        consensus.BIP65Enabled = true;
        consensus.BIP66Enabled = true;
        consensus.CSVHeight = 419328; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.SegwitHeight = 481824; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.MinBIP9WarningHeight = 483840; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        const size_t N1 = 200, K1 = 9;
        const size_t N2 = 144, K2 = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N1, K1));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N2, K2));
        consensus.nEquihashN1 = N1;
        consensus.nEquihashK1 = K1;
        consensus.nEquihashN2 = N2;
        consensus.nEquihashK2 = K2;

        consensus.nEquihashForkHeight = 95000;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000003cbab61c14c");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000c6a745906efa830d5946f68518dcb32dca077cdc49b757613bf956229d2"); // 382610

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xd8;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0xcd;
        pchMessageStart[3] = 0x93;
        nDefaultPort = 29333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 280;
        m_assumed_chain_state_size = 4;

        genesis = CreateGenesisBlock(
            1512832667,
            uint256S("0x00000000000000000000000000000000000000000000000000000000000002e6"),
            ParseHex("00070c35670ed414e88f629ba7dae8dcadcbb16419221ad948059cbd018917e2b8bec09405ad14327e810ca560c67568235f72a9116a980b83f6c132ddaee132b7dceaccd2cd473d94a492b14d50caea2c998962008d96dbe4d023f9f43583b85552a401883b1075190c19808ebe4b06d5a3ede1535dd4068587e1fb1c961a04f70fc2c8c282fe5986bf5bc1ec1e55143e1fa12812444e3c2915b1810193d9a2f0408d474f59237f074a4e773808162efe813380f2a4acb20607b40e133385c1f815cd533abc3ab921f6e26cf2724bb95aaf1f563ae2149cf3fbe12cf27e5b21b7baf70aff163d35588534c4693d87e775c9728cd9e9079a9e7e21412626238eda92f7ad62372a910fd82fff185cfbd3d42a23e73c04dc42cb192204196231b222331016e16c2a20cb3842509a99370a02c7efdb9bc11b78f511b548b22cce5199abe1c849f994fe69a903bbfdbe5dd0025168cd45c96c3d4d458132819dc515b41c3a8544089e2554c568fa0fe802c123b63447adbc8ad49f9d208b62ad588b3f2ab0141210e0efe94b37b49b667568f4859767a1cc3397b5dae222e3ad1ebd8bfe6d27104bdbad5a4d6bd6b0c473a2b9e1efbf4cad9ef27b1734bc0cb56515bf586cc2b74ca65b71bf02361fd2210ce67fe25547bace2fe2fef9e5ec21854c1e6fb52f7a5ddb45999c3390a843bcfaafdbc55bf46b0472045e2fee4e94e98d1ebc01ffa94518ee6dff7a161115e8c5e688c6eab316a651db392055fafef65a5ed7069a772e2bcbfd8e9e7195cb187f2d837b769f6b7726960720b1a77fefacd2b33dc61f9739d78636b8a1078f6859950449d3f422e1fbc45d5030972ab06df45f5d23fdff1c4a256135774d133cbbae07771c27360ee54cc5fe54d393c17a74963a68e8ae5e017f480f2550b4d9c4720cb7b3dd47f810d0e12aaf047a2b3d003f78ee1bc94910640ed9f96875c2be854b95ccc31bd751f06a9281631fc87406d2bb3a6d31d45f376a22bbb325dbfe3a13f93d356dc2c41ebdbf8458a66735222d49a823c3cf9493aa0188deecd6f9a3dd2f033146045d9930ae09e2b0137dc877dbbb015f5d965e496f766c7a94de9fa7e55b8e2fea1aaf81615c94f94af9ebf5ebab5e99929d6947b6ffd983b6789f222551ebe6dfa899e35ba19ac8d0e6500e2fb3d71fd572077055d7db468f84589851aee7de7643854c9df7ec544ccdcdd72be08572a7b7048d57b859f19ed9b1b907f763c6cf60b4bfbc3e780f62ee8e66f5cf1c2b963928f20ddf20ccbb277f95cebee326a99080f9a2d60b4e805d444826fe6c0ac8d1c8f14496d73abd50131a65360057a90b51676de2316718f1c26aa47426280d6f8ba0cda4775db73346e6ae6ffcb68351bca27b48ee96751b2463df6bb2881a2ed8138e615478363601a0cb32dc0d4bed1d7e416f13baf2bad22099716423afd2cd79ca13aac929c26cd3147fa9de8cff0cb20ec3ec4f80d2e531d82e727ff1a5436d601f4c2ad2880ed50992b1fad1deadf8a659f154e25edbb5d891091ba473471070ae867ad59692f340fa0d5010d7d914d3b0abe7a1557df47d719b355a0984c6db898b36125781999b3a39d7e838f4efe2fb30df49bd5c22af43ea1656a363bc9fafe9f4622035b77e224cfc51230869d77d6e86ac09f34670c3f634aec89a759376e70f3dfbe572b174958e62613a11bcc6599c29360f640bb93691f0dfc6d1ecd4b148767c1c00f13dbc62f4209f1934b55bca72e5ff92897920bd6d1f6f0f0601093cd0fe1b02d7c24b1816855aede3da2a277ab12d13c5491d4b1b4c59607ea8f027ee5012c159dbc9551340ef820e0babe096dec30b8838d89dc0ad10eb4d1a5672d67abca3e7e84111c61ce0280c8df8392513"),
            0x1f07ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0003f52e78c166a7f44506c152f5e1df1577f21cb7062f863dd8f9a47e125ff9"));
        assert(genesis.hashMerkleRoot == uint256S("0x87800ace8ce2299bbf33ac3f76186ee66be9d7de9a9e22cdba040d3c4776870e"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("dnsseed.litecoinz.info");
        vSeeds.emplace_back("dnsseed.litecoinz.org");

        // guarantees the first 2 characters, when base58 encoded, are "L1"
        base58Prefixes[PUBKEY_ADDRESS] = {0x0A, 0xB3};
        // guarantees the first 2 characters, when base58 encoded, are "L3"
        base58Prefixes[SCRIPT_ADDRESS] = {0x0A, 0xB8};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]     = {0x80};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "ltz";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            {
                {   293, uint256S("0x000094343dc23483c26239f71603980a5c56062c061b81a6b6f30a77e6717d41")},
                {   586, uint256S("0x000015256f276b0bb1d8e3b601ac37644e76cf860d8bc565aa1ff82fc0a6ef3f")},
                {   879, uint256S("0x000083828428d8d2f5245d9d4ada17df9418ae1c320268f477a853f800df3365")},
                {  1330, uint256S("0x0000c242f621ac3a22e6cd230b25fc27800082072724cab678f5e32c12f8d1f8")},
                {  2659, uint256S("0x00004c165c02803abd5cbb066a7b70328efa8e0345fa7658701af96c53458da8")},
                {  5317, uint256S("0x0000486d6d3e2587fe0c3f48fd74ed21676202bf1867648dbf4c1a52f3659d4e")},
                { 10633, uint256S("0x0000005f809e79671f57d4dbb0ad8777d1e4a2f07d72e146316271567e6987b0")},
                { 21266, uint256S("0x000000126cfdf6cb5279df2a53e79ab30ea0f7336c794120c3197b9373908dd6")},
                { 31901, uint256S("0x00000088282df4c26a47bea22cb313a29ffe9ac8f30aa7de0129ca2c3a770f9a")},
                { 50000, uint256S("0x0000003f6762c60d9699a212e819a7d6630c6ea602a475908bfefe962f0803bb")},
                { 60000, uint256S("0x0000001334ddb7af2a2c17fd6dc0f7d0c0f6ba077403a0aed763b304001b7402")},
                { 70000, uint256S("0x000000094161a482b4d2f6dd2a261bcd6962a2c00a5e6ba94002d0633ce8912e")},
                { 80000, uint256S("0x000000157847bab44d199ad34954da98910c726575716270771ee7e32ceba1d6")},
                { 90000, uint256S("0x0000002564e3694cd1240d570fdcf9cf36791b2e2c462040fb78af34959dd02e")},
                { 93096, uint256S("0x00000038101895ae9add3b5d288db258b053c4bdc39642aeb6be44f7f53bc929")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000000005f8920febd3925f8272a6a71237563d78c2edfdd09ddf
            /* nTime    */ 1529323588,
            /* nTxCount */ 95703,
            /* dTxRate  */ 1600,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP16Enabled = true;
        consensus.BIP34Enabled = true;
        consensus.BIP65Enabled = true;
        consensus.BIP66Enabled = true;
        consensus.CSVHeight = 770112; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 834624; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 836640; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        const size_t N1 = 200, K1 = 9;
        const size_t N2 = 144, K2 = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N1, K1));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N2, K2));
        consensus.nEquihashN1 = N1;
        consensus.nEquihashK1 = K1;
        consensus.nEquihashN2 = N2;
        consensus.nEquihashK2 = K2;

        consensus.nEquihashForkHeight = 435;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000f1eb9b");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000000000b7ab6ce61eb6d571003fbe5fe892da4c9b740c49a07542462d"); // 1580000

        pchMessageStart[0] = 0xfe;
        pchMessageStart[1] = 0x90;
        pchMessageStart[2] = 0x86;
        pchMessageStart[3] = 0x5d;
        nDefaultPort = 39333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 30;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(
            1511954736,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000f65"),
            ParseHex("00e7097053c67d09d457920796dcebadfcc6f469240eb5ef9bbb198c3aff994217d6afa7ea0bf415aaae194344a0c848f5f93d6d853cc1ad4aba4195940af83183265a331ce64efc9f63e6d7fd02ca27ad1c0a59059b8b245c0b5b5769698239cf9bcb80db0d5988dd2bfc2ce6e95313c711bea49f316976cd866d2d833b07a5aa27989c55ddba9371d8f9d92242c44cf7604f1b0b85675e4c18c9b9c82cc65568fd9344637ae9790315c65faf0e10c798c2c1179aeb8080ad665c0c503d74cc0f978fbf77abfb06a53ac142eac15ab91c1e087791bc9c538515cf8f021298e8eb7267839b0c2f0b3c52889cc624b83ac6b20876f3abd1c406518bf40c875614648e4c12f9c781590e996e25919057f9f617eacb4bab9d02ddeeb27c8ef67393fb46be5e794d1073853aee2773db821ed13f72f9421cbf0a3932ff1b1405ddb7d844af1328161d7cda7906a85c9c5d73021f1e36fdd2042bd949d3564bf95e05731bd7056b0a703df6248dd373249ba51600dba051a7b95d56c72313a9fe7164d57b49ee83e8f869509212cdf5ee06470887559fb1b6f7eaac39ecf2cf7b77517bff99120a24840088532c7baa077239324841c7523d9ff7e042b64334a5b334efe53ac47480ec86dae65d9c3fcc0e0905a707db00250da931319fdf5354e54c6ee9311ae4af4007174b2372774aefb7e292d7223dfbcb220371de952656c860f3e38252959fb0296c696ec5d915d5ed810e457705cc7b76cd6861b3e680c89a8098277046d706ba8047fcde429e2861fa7dca00ff1a5e5e02eb12adb37abfdfb256d4767091c9c1b077c7b60b646e358a1ed1171264c0cdfcd3d11f55fdde24fe1f44b9cb7b6936f1cd42b26178dd426498ebb91f8a150732ed1af34ae5e89f15437bdb2e5aa4147af79b5c742f190624b19747cd593e986058a678a3d7546201b8893fa0e890c7e5a7c3a66221a5eda1a5b7d0c7171d6e3e464ec8a16ded599c875900df5dd5fc45560a19e6c9314dab78795ef348544f7e917da5d4c15e49474b487b3461c3b9601546417987657c3c16f5ed14a58752200de1717863e3199efb49bf97967fc3867e051f9c73a16071e21d19685dccb5c70c173f1c8130353b6f16dbf95b393d73c8a03afe019ab9f8698272807dc0331f07618ca8c8226ef01e1b2ee9599e260495ce17e5c279ae5584e1cbe1da50b08ccddf6b230878f97e82ca143f4a4e41b1dc7e650f1b103e73da13eb2e93184e04fd35fb915ef67e6cdae06effdb4e39fe0b79889c8fd18556d3e45fa0f995358536c15d09a8b8b7ef585dcb229891def2d9eef8bfd72b5aa43531acee7f2a5fb3cc98e5b3a1ecb5c58c43f66eb01c79e6785d8cb799f53432c69d7e0e42172d132cf93d0f9b2c6390b1b31705b6b7bae8216e895df5ad0402c29be10db92389cc3380e07cf9d76a4d45b95e391898e679cfd64096f267d2dea03af9a5e3cef1b6a50950729406505c2518be51dd84715944a0b67299116d9707e4b3626dfd62f7bb0d5ee810ef89b4dcb3c40357f4f2ed70dcc1f907d11199bd15c754f93d04630c71fa683325f605d5937130e91ab081571cbf64150ab6caf3ce0843292c4bb0eef8fa816b0c5f9b01ce69275f82fd5c1fd71439f9787b500a277842fd68df059e944a5fae619bdfbde696d37ef9a663ee9a3fcf06a17db961821ec36eea695e17df77df45cffd658f06a9858187207a8bc988071d1c6f78623254793d9e1f6e6de23616488d9605f4d853eb069af068da4eb6097252ed9160642d499130d86996a6711821ed393911ee39cbe8863e676155d25b2fbd3b1133151c8c2a1a5d96dc271b5e7791e4822900c413b11b8eb31fa33654b1fddb5ae4e94984944a964b7005c45d6fed16"),
            0x1f07ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000777e63f7c2efb3c554405a07a4f3dd1def8ea5cef4fda65b2c57247171141"));
        assert(genesis.hashMerkleRoot == uint256S("0x87800ace8ce2299bbf33ac3f76186ee66be9d7de9a9e22cdba040d3c4776870e"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("dnsseed-testnet.litecoinz.info");
        vSeeds.emplace_back("dnsseed-testnet.litecoinz.org");

        // guarantees the first 2 characters, when base58 encoded, are "T1"
        base58Prefixes[PUBKEY_ADDRESS] = {0x0E, 0xA4};
        // guarantees the first 2 characters, when base58 encoded, are "T3"
        base58Prefixes[SCRIPT_ADDRESS] = {0x0E, 0xA9};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]     = {0xEF};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tltz";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;


        checkpointData = {
            {
                {0, uint256S("0x000777e63f7c2efb3c554405a07a4f3dd1def8ea5cef4fda65b2c57247171141")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000b7ab6ce61eb6d571003fbe5fe892da4c9b740c49a07542462d
            /* nTime    */ 1511954736,
            /* nTxCount */ 1,
            /* dTxRate  */ 0.1517002392872353,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Enabled = true;
        consensus.BIP34Enabled = false;
        consensus.BIP65Enabled = false;
        consensus.BIP66Enabled = false;
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        const size_t N1 = 48, K1 = 5;
        const size_t N2 = 96, K2 = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N1, K1));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N2, K2));
        consensus.nEquihashN1 = N1;
        consensus.nEquihashK1 = K1;
        consensus.nEquihashN2 = N2;
        consensus.nEquihashK2 = K2;

        consensus.nEquihashForkHeight = 100;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 49444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(
            1511954736,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000007"),
            ParseHex("0d728a7a610f130fdf24bf911ff28730b51c1e748dfd4646564b4e30dce57bf5a6b6233e"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x010539fc03180019d4de063a7fc0089e5e7d500ed5e943936ea7ea0e7aacd54a"));
        assert(genesis.hashMerkleRoot == uint256S("0x87800ace8ce2299bbf33ac3f76186ee66be9d7de9a9e22cdba040d3c4776870e"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x010539fc03180019d4de063a7fc0089e5e7d500ed5e943936ea7ea0e7aacd54a")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // guarantees the first 2 characters, when base58 encoded, are "T1"
        base58Prefixes[PUBKEY_ADDRESS] = {0x0E, 0xA4};
        // guarantees the first 2 characters, when base58 encoded, are "T3"
        base58Prefixes[SCRIPT_ADDRESS] = {0x0E, 0xA9};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]     = {0xEF};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "rltz";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

unsigned int CChainParams::EquihashSolutionWidth(int height) const
{
    return EhSolutionWidth(consensus.EquihashN(height), consensus.EquihashK(height));
}

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
