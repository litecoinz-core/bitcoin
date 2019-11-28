// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/setup_common.h>

#include <banman.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/equihash.h>
#include <crypto/sha256.h>
#include <init.h>
#include <miner.h>
#include <net.h>
#include <noui.h>
#include <pow.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <script/sigcache.h>
#include <streams.h>
#include <txdb.h>
#include <util/memory.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <util/validation.h>
#include <validation.h>
#include <validationinterface.h>

#include <functional>

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

FastRandomContext g_insecure_rand_ctx;

std::ostream& operator<<(std::ostream& os, const uint256& num)
{
    os << num.ToString();
    return os;
}

BasicTestingSetup::BasicTestingSetup(const std::string& chainName)
    : m_path_root(fs::temp_directory_path() / "test_common_" PACKAGE_NAME / strprintf("%lu_%i", (unsigned long)GetTime(), (int)(InsecureRandRange(1 << 30))))
{
    fs::create_directories(m_path_root);
    gArgs.ForceSetArg("-datadir", m_path_root.string());
    ClearDatadirCache();
    SelectParams(chainName);
    gArgs.ForceSetArg("-printtoconsole", "0");
    InitLogging();
    LogInstance().StartLogging();
    SHA256AutoDetect();
    ECC_Start();
    SetupEnvironment();
    SetupNetworking();
    InitSignatureCache();
    InitScriptExecutionCache();
    fCheckBlockIndex = true;
    static bool noui_connected = false;
    if (!noui_connected) {
        noui_connect();
        noui_connected = true;
    }
}

BasicTestingSetup::~BasicTestingSetup()
{
    LogInstance().DisconnectTestLogger();
    fs::remove_all(m_path_root);
    ECC_Stop();
}

TestingSetup::TestingSetup(const std::string& chainName) : BasicTestingSetup(chainName)
{
    const CChainParams& chainparams = Params();
    // Ideally we'd move all the RPC tests to the functional testing framework
    // instead of unit tests, but for now we need these here.
    RegisterAllCoreRPCCommands(tableRPC);

    // We have to run a scheduler thread to prevent ActivateBestChain
    // from blocking due to queue overrun.
    threadGroup.create_thread(std::bind(&CScheduler::serviceQueue, &scheduler));
    GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

    mempool.setSanityCheck(1.0);
    pblocktree.reset(new CBlockTreeDB(1 << 20, true));
    g_chainstate = MakeUnique<CChainState>();
    ::ChainstateActive().InitCoinsDB(
        /* cache_size_bytes */ 1 << 23, /* in_memory */ true, /* should_wipe */ false);
    assert(!::ChainstateActive().CanFlushToDisk());
    ::ChainstateActive().InitCoinsCache();
    assert(::ChainstateActive().CanFlushToDisk());
    if (!LoadGenesisBlock(chainparams)) {
        throw std::runtime_error("LoadGenesisBlock failed.");
    }

    CValidationState state;
    if (!ActivateBestChain(state, chainparams)) {
        throw std::runtime_error(strprintf("ActivateBestChain failed. (%s)", FormatStateMessage(state)));
    }

    nScriptCheckThreads = 3;
    for (int i = 0; i < nScriptCheckThreads - 1; i++)
        threadGroup.create_thread([i]() { return ThreadScriptCheck(i); });

    g_banman = MakeUnique<BanMan>(GetDataDir() / "banlist.dat", nullptr, DEFAULT_MISBEHAVING_BANTIME);
    g_connman = MakeUnique<CConnman>(0x1337, 0x1337); // Deterministic randomness for tests.
}

TestingSetup::~TestingSetup()
{
    threadGroup.interrupt_all();
    threadGroup.join_all();
    GetMainSignals().FlushBackgroundCallbacks();
    GetMainSignals().UnregisterBackgroundSignalScheduler();
    g_connman.reset();
    g_banman.reset();
    UnloadBlockIndex();
    g_chainstate.reset();
    pblocktree.reset();
}

TestChain100Setup::TestChain100Setup() : TestingSetup(CBaseChainParams::REGTEST)
{
    // CreateAndProcessBlock() does not support building SegWit blocks, so don't activate in these tests.
    // TODO: fix the code to support SegWit blocks.
    gArgs.ForceSetArg("-segwitheight", "432");
    SelectParams(CBaseChainParams::REGTEST);

    // Generate a 100-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < COINBASE_MATURITY; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        m_coinbase_txns.push_back(b.vtx[0]);
    }
}

//
// Create a new block with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current chain.
//
CBlock
TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
    const CChainParams& chainparams = Params();

    static const int nInnerLoopCount = 0xFFFF;
    static const int nInnerLoopMask = 0xFFFF;
    uint64_t nMaxTries = 1000000;

    unsigned n = chainparams.GetConsensus().EquihashN(::ChainActive().Tip()->nHeight + 1);
    unsigned k = chainparams.GetConsensus().EquihashK(::ChainActive().Tip()->nHeight + 1);

    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlock& block = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    block.vtx.resize(1);
    for (const CMutableTransaction& tx : txns)
        block.vtx.push_back(MakeTransactionRef(tx));
    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    {
        LOCK(cs_main);
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, ::ChainActive().Tip(), extraNonce);
    }

    crypto_generichash_blake2b_state eh_state;
    EhInitialiseState(n, k, eh_state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{block};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;

    // H(I||...
    crypto_generichash_blake2b_update(&eh_state, (unsigned char*)&ss[0], ss.size());

    while (nMaxTries > 0 && ((int)block.nNonce.GetUint64(0) & nInnerLoopMask) < nInnerLoopCount) {
        // Yes, there is a chance every nonce could fail to satisfy the -regtest
        // target -- 1 in 2^(2^256). That ain't gonna happen
        block.nNonce = ArithToUint256(UintToArith256(block.nNonce) + 1);

        // H(I||V||...
        crypto_generichash_blake2b_state curr_state;
        curr_state = eh_state;
        crypto_generichash_blake2b_update(&curr_state, block.nNonce.begin(), block.nNonce.size());

        // (x_1, x_2, ...) = A(I, V, n, k)
        std::function<bool(std::vector<unsigned char>)> validBlock =
                [&block](std::vector<unsigned char> soln) {
            block.nSolution = soln;
            return CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus());
        };
        bool found = EhBasicSolveUncancellable(n, k, curr_state, validBlock);
        --nMaxTries;
        if (found) {
            break;
        }
    }

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    ProcessNewBlock(chainparams, shared_pblock, true, nullptr);

    CBlock result = block;
    return result;
}

TestChain100Setup::~TestChain100Setup()
{
}


CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CMutableTransaction &tx) {
    return FromTx(MakeTransactionRef(tx));
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CTransactionRef& tx)
{
    return CTxMemPoolEntry(tx, nFee, nTime, nHeight,
                           spendsCoinbase, sigOpCost, lp);
}

/**
 * @returns a real block (0000003050f18d4b4614b499fd6c98c90ed80fb5632790be031e120291814859)
 *      with 2 txs.
 */
CBlock getBlock13b8a()
{
    CBlock block;
    CDataStream stream(ParseHex("04000000103e9b3947c6b51c7d86664ad33f337b1f52b65db1add86cdaece03709000000a89fa4bdb21cac2ad78003b97b2805dfa3d069c38461bc930f9249e9abc4703400000000000000000000000000000000000000000000000000000000000000002ce2635af694411d2fffff3d52a54906000000000000000000000000000000000000000000000005fd400500cde9bb8990fe9b907913268b7af0f5c9731236ae693124c6deb20663e85449a3eb7a92be7b407fa79a12683c11445edf2b7a907908325c824b0182ba8bc6292242229f6652cd68e494d016af26e7d2291ec7630ee4eb46c89be74d1dd4339ec3595074fe041e984c180a93c066f43835e256424bc99a9aa0d3f77d82ed1502939834e0be61af8172a7dee1af11e95d353c083adf95d83d18e6ad906d44a607ebb67d991731292705c4291875a11ca58e27735179f36689fb6f9a4d9005c5a7aceee939edc43c22d87520794a2cd11d457d08e2c0e01c89d141e7b503fcf5464e7687ecd9d7022a2e3a446becf867c91f82d8619b26ee506d159ef50a8aa3e6f7084b61e577a3b82d6c47127bbe9b1b0113dc1120c9d9981da3d09600dbb37dd2bad9b67297192313e3e10e8c131eeb5b804f66447afcbdfc70ab2c6db688106751c7ab9ed358d7ca1f017b25d7cc7e00f72b33e30895ed6af677cbdb406b53a9713edcc42066eed4086ed2b988e9a274114d98c62e88faecab0c3ff53301087953e0ab340aafb80a7377fcde63393730555e03131d3de13f4636c9c34fb6b0cf1c9e5910b4fd2f974a36b6e7bb715ac75f55f583979b85a21bac5ce1198fd1ed6a77821c122dd8b5e9bf9bdc8d2edd81b0d2d50310fb6e4472fe5cfa7a351e56c3983289c1df481990d35c90f44a7fd13a2294799c7f1401c19ac9248b0600f5bee35c1ea8ca25ced899352a27c2fd9c5b60708bf440d460ed42973a38b134adf009796559f197d4b1442c41289cabcc124c9dd38eff11031efb37749bf7eee674b730e9fa91505592484c0ea2f19ebd4fe03ec2ebb592bd32132d745b2d9dd93327722e9d9fe4c1b4636cf2bdec5c737d12bfecac0f28a57df845b9b2822695efa34eb0bb036a79dab4100d190956b6b0e9c1c463d78bb341dd6d18f64ac40170e2dfe952ac45fe76d0bfaa36e7a8b1f69af24430f6eafae0a4a34bcc0ca331ba2d038a0f2236c3cf029157518e4c02d3597ee7675e4b784631197755b53eed2b0b279253afdbbb0674523afb6b972e3fb3c00928ffdf63f07f5fc0ea712ac2338bfd082ed4f0d82101d186279aeb8fd33a73b0093d1acd1fc5b4b18c1e6aab73a6573866dd6d9321abd69ad4f6ec6bbe9e4685d5ea79f6519fff78078282672b8df5efd35bfb047f476927a16c2ffc9a84a98e3ffbae6e233e872a06477aa48368a793a0ded256c65f2c4cf81952bdbf09f1f5cfdc920bf0df0c63755fe6080e695b776005356d87dcc8dc91fd747a26d6bcc3a8c79ab19f3990073d6f7c711fc7619ff8a2ff016415edcbadde9c0d37b3c5bf96e896d79b7a4727064dc171d2233349111397824aed911d3d02af82ae11620d3189f24d331c27c12b5fc9114f5ecf9295e5f1c3552611237795d102c6fe02ae337e87fb5c333204b89005dab074db9131a8b4574062f3c55530046c39328d3e19079ffcf20ddd8aa60dab318987b6f59144ef0e5a65ff98de31262142043d12b6397067954b0d7c1f4d6405bdfc6d03496e35bae81359996c81a6d742d756295f97f3574c22be36c814ff40da10a7904fea9556eb1d5e59a017ed0c2c9fd34b6d030af3c569fa57351b6e1658c6489cfb22075ffe0b0da236fabefe5dae7f3bbd61ef07aaa89bb89bf5b32997d3eae6e5d0d2dd50bd27642075a9af51095414fe0ca28de59c7176fcfadf9f2d1193ae883185bfc856ce15ea26f21c11b88bd469cc6a6bc4df901fbc231905695107617716f0a6b8e583148792a516208cdd8d59d3209c7013c365f97e423534952d3aca8d9ae77d7ca409b4313ab58f6f7dff86152024d7c1caf4fd4a21e7493850de2a8f357fe1b21b83e9b3b7c9faebb38474edc1662ec5a75c51528d0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3102411f005a2d4e4f4d50212068747470733a2f2f6769746875622e636f6d2f6a6f7368756179616275742f7a2d6e6f6d70ffffffff02f2656d29010000001976a91457bc5e7e48328d84194f57667425ae26357bfb3a88ac80969800000000001976a914cc9fee1128f4cfe550cf6a30e76fe9fc7804a0ba88ac000000000100000001446142a3e9cb9cac02830b03402f73dad2c6a301df9950f98da81954f696a279100000006b483045022100dbb0e7398242b0ae0f0da015338c9122d7087486c7b5d3a3a076ca16b7bce70602202bd5ae188b7469171d6511dd66b92faff71fab09bf59779a471d82a1784d849f012103efbe831724fb52e2a18253769394531421519ed47505bad74e89ec65cae58b20feffffff4aeae5a700000000001976a914e0b0f6b9f742d008ab38e4e4439800da46f660fb88ac89e31111000000001976a914f31a01b041c8c6960681c56237a00a07ddcad5c488ac2dda1e01000000001976a914327f428529df34ba949b7bbfafb77b9ed008fc2588ac07a94102000000001976a91486eba783cd90484614a6dcb7c00a0299ddc0687388ac89bb3703000000001976a914bdb8a9b676fe11bc1e4614aec1e5751c62d6788c88acd0279d00000000001976a9145310a42518892c48beae98548a8bc8d06e7b1b9988ac394cd700000000001976a9149238fa8aaa94f94e3cdbc29939b2a35b01a960a888ac77255005000000001976a9143b5dbf682db9d59271eeb2185e2fff5dc1ae207488ac2e49ad04000000001976a91454058d2ae49b5b14eda41b2e1ca3cdcf80c9e54f88ac25648f02000000001976a914fd8fc982964ed780f579764076150832649edc4688ac36e3ee00000000001976a9149cdeda0b3a0fc9fa3de83b70e1349b7b6956c52b88ac98605a01000000001976a914b638295bce142f2c375e5a895cf5862ffd2d0e7588ac4037aa00000000001976a91464adc4b3718b3a272dc17bbc2dfce3780b56251788acc35fb200000000001976a91413e7aafc1b75b9b6da0a7f71fe0930017aa4aac488acbc4d4c09000000001976a914612130d2320415c3435297ea971aa2573375649c88ac8ce0cd00000000001976a914922beda9aee1d69feac07bb75182bd8ffa6808d088ac5b7df200000000001976a914b846c937e9c5e4d6b0fa27ec3f05ef8a47e6889688acb11fc302000000001976a914f69b9d5d852c19d02663d1bc220589da21eabcc388ac429d6903000000001976a91482db719cbc0c844c30046af33074c85ae0065b5288ace5862002000000001976a914e8b7fb695b9422dfb5de7059884bcf02d3f710c388acaec34b01000000001976a914e345b58c318d7b3adb439bdb54c1d74c537e99b888ac99c6c701000000001976a9141c1905fd4cb295adcf6d4ee97a90904acac6552c88ac1e660604000000001976a914451c46e731a1e737c4b540708b3129bcea959d2788ac6a9fac02000000001976a914be5f3c038eb9fecb2da32541efb3a9da0af7e7dc88ac9b7c9206000000001976a91456193f743bd58ee4a2c91d1051bf4d3a33ed154388ac9ca96002000000001976a914e8752ee36b50a68a5666acc9b61452cf8157700b88acb5579f06000000001976a91472aaa58466aece3b9185473675bcf4115104f09788acf6c8fd03000000001976a91477e45823b454aab3e14aa110f8e21666423ec88e88ac311e7904000000001976a91448ad203811322f400d29083bdb1c2a970ff29d1288ac4e1bbd03000000001976a9146a924043b62b1685d47982491e7b3c7a1b1a38bd88acae9ba501000000001976a91414a042a7eb96152fc6617b6894f1bb36974f6ab288ac4b198c03000000001976a914a948647cf7feb0f340f5e8d50dab38c14618b42388acd33d9802000000001976a914b443961a9d4d54f14bde254bf5746db1d0cbd3dd88ac21cc0201000000001976a91488b182efc126a70e16b66e9c3e689bf8786243d088ac8b56a302000000001976a914b3d8544958aa9d50ee0b4ffb3eef8e6a94648c5388ac3cacac04000000001976a9144775058ba8d39337c0ed339f57785df5cbab690788ac12705201000000001976a914761a3c9cb01ceda9bb506464dba6c4cf85bc292a88ac8bf43401000000001976a9144080d4ef8b0297b897e07714f3d66048ed1bae4f88ac6dd60505000000001976a914825296da4d6c2893edea657e202fd59a3c21c27888ac8aa4c202000000001976a91438ebcb9a38f76022e9ac62d18b4da9a34fa8ea8b88ac468a6501000000001976a914ea165d3c14b9677985878141f74ee3633613a2a288acd570e502000000001976a914440e83611500fe554094023a1cce72959f05f32d88acee397901000000001976a914aa9a5fb016c907d761dab4189f5cf703b37b270288ac9e102602000000001976a914055ee098088cba9ce0ba7bab33984eb30cecaf5788acfa66b401000000001976a914dd0ea3fbf74f48a7bdafa618244806acbe0d517588acce513101000000001976a914e6bc3e4e5b4aaa690eb6727cff354510c1d995ab88acb7f08e04000000001976a914684bd4335e72a1333180aeca4cc7918f3a3fbdf988ac80cb5d02000000001976a914672808fc7c366d04b6da6efdd7bfc7373566a39c88ac506bc702000000001976a91405c475cb31eba3a9eafb3f1f691141a87871315288ac3fc1ce01000000001976a9140d928e37ba6526b0b0851b1c818cb811d06ec7d088ac32b5d506000000001976a9140dfcba5a588f4468cc774cb319a48e57abe71cff88acb678cd00000000001976a914c3c31102b03b4fa7a8080d0efa3f72717c9a5f4188ace399a701000000001976a914f22374fece8c358b8b16ac96cf6f4f5f9218bd3788ac51e9e300000000001976a91492e1aca0c9cb7f90c381dee55d645c90d37496c388ac00656b02000000001976a9143c93d25426cc8beb291e91e2775615db6bb7cf7188ac4923dc01000000001976a9140fa15a5badf9f9aa3b48662f3366ab7b4a79a10a88acf908d200000000001976a9145b7cd317cfb23b47c07c373379a8bb50bcb4bd8088ac63611001000000001976a914aa8a3c2f8e4176b1cb35d36f39b9fe5e2586f20b88acf207cc02000000001976a914460711599dea4d6737de4531ee66a0d98daad0bc88acec29d300000000001976a91442f29a29c01044b9ec38ddffe5dedd1c9c11554988ac62661b02000000001976a9146ef6268f728f8c0f712dfc1efca8383ec6ae347188acb1d6a606000000001976a914b58804f9fb14b3be47beb4ea4678af5f6b653cb988ac2766820e000000001976a914469ef64a0673b2f41b8e0021bf8d62c2ee65124a88aca37bf603000000001976a9142a873664e4dccf597b74776e0d2fb5bb97aaac5788ac01c1930e000000001976a914cf82e1fb881e376b7e7498e49e909dd3862d2fed88ac57063f0d000000001976a914dabcdbea7d95c29f32ca61fcdf429adac551b10f88acb55c9602000000001976a9140a07f515204a3bb05a2d5bd20d58b55022777b6388ac3e6db506000000001976a9147dc8434480550516ceb1134d20e294e10a30fcb588ac13813602000000001976a91407b47dae0b5d90c2bf89db37ea0ea0c817f787a088ac61617104000000001976a9147b91c25c8256c7e6e6d033d03b89e0dbb0a5ba1988ac9bd15a03000000001976a9143f9e5e6be3c37938477522f2a45d9cef988b705788aca11ef817000000001976a9142f681e4913a1e7b684141f175e56cd10c699b09388ac6675561d000000001976a9143be45f665824e00f3a53ca7c7f2c593e5c90c6ab88aca24db004000000001976a914f6d50782879d08244eefb82c80414aa90b32d59c88ac361f0000"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;
    return block;
}
