// Copyright (c) 2011-2019 The Bitcoin Core developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <crypto/equihash.h>
#include <miner.h>
#include <policy/policy.h>
#include <pow.h>
#include <script/standard.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>

#include <test/setup_common.h>

#include <memory>

#include <boost/test/unit_test.hpp>

struct RegtestingSetup : public TestingSetup {
    RegtestingSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(miner_tests, RegtestingSetup)

// BOOST_CHECK_EXCEPTION predicates to check the specific validation error
class HasReason {
public:
    explicit HasReason(const std::string& reason) : m_reason(reason) {}
    bool operator() (const std::runtime_error& e) const {
        return std::string(e.what()).find(m_reason) != std::string::npos;
    };
private:
    const std::string m_reason;
};

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);

static BlockAssembler AssemblerForTest(const CChainParams& params) {
    BlockAssembler::Options options;

    options.nBlockMaxWeight = MAX_BLOCK_WEIGHT;
    options.blockMinFeeRate = blockMinFeeRate;
    return BlockAssembler(params, options);
}

static
struct {
    const char *nonce_hex;
    const char *solution_hex;
} blockinfo[] = {
    {"000000000000000000000000000000000000000000000000000000000000001b", "0388de7010e51a1b6b0f988852049c0baff43253986c536d217fdf48ae9fb5460bbea796"},
    {"0000000000000000000000000000000000000000000000000000000000000021", "00896035e3e77223d20cbac3edf322f125c31b256112a2535e9fa52f9c62d887cfc6859c"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "02dec53465fe0d9b411454e214c6ad85f7190b7c504b252bda79c33b63e0b8b57dc1d5e5"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "0275b1b8f2c9e22d8a03c91ffd20f32cdd3d0c8f0ff4f4561a75dd129a8a74b92d62eb9f"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "04e90ef0e4b79e73784456e2f387bef257e1118d879c518b9251ed14e7a93d72aad55133"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "05db522a61953172d157db263f16465269c432af325ed9c586b39c55ee95baf755a25b3e"},
    {"0000000000000000000000000000000000000000000000000000000000000010", "05a81a70b384d35bf436c8ad9e143b7555040704a0b5fa9daed18f12c765f71563fa199d"},
    {"000000000000000000000000000000000000000000000000000000000000001b", "11a40695150f99a9b52aa81916b3aa910b65271ccf1df2933d5cec283137ffb3ddb691a1"},
    {"0000000000000000000000000000000000000000000000000000000000000012", "0830683812c45d912d09cb8b7480fe3515270e2a66bed1be26353d101d31fd524142f5c7"},
    {"000000000000000000000000000000000000000000000000000000000000004d", "04250165b22e1c9dbc1089b35b38a76eb7bd0552da185315d0e5791cfa6313c20bec9132"},
    {"0000000000000000000000000000000000000000000000000000000000000008", "0be6ec1e50cda643ea5a3aeafc46ce66bde412dd9e51337be0e10f306f937a770499c5e6"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "007f5e77129528e14f07ff211f618b839fe711c9d1c9d305cd4b8724d549bf83daf9cd40"},
    {"000000000000000000000000000000000000000000000000000000000000000e", "0750ca95a4055661d91168267d06a5d77dfd315f0d47f3236903146255a4bc670eba27ec"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "027d4c4d3bb63b13950ed5461154bbd18593142b4f4c163742e5f7261459ff03bdf2bf83"},
    {"0000000000000000000000000000000000000000000000000000000000000036", "0b445557a12f1ac5a71ad7e8f4c32ef10f531848877e71eac097792637cd284d0fef7be9"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "0dad0ef0ba5d86dbf227684d3584efe551fe0e545ddde1f7d66bcd425da5b405f4f667a2"},
    {"000000000000000000000000000000000000000000000000000000000000001b", "01010dd80256fe7d4407b72319644ad23342070a4b5b44f3a6e19b3ff0566ef563e9c355"},
    {"000000000000000000000000000000000000000000000000000000000000000f", "05556e79b9cf7ef3b40969190eb243f2b7c41ac04cb8d5b506cbf74ae294fa0a1df317fe"},
    {"0000000000000000000000000000000000000000000000000000000000000008", "18d31250e42dbd999532aad59cc40f4621502efc36ff34fcef01a439d2b05b97a426a7b0"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "06d10b2b247eaa77ec27b80dbc5532f7b1e82164195b72dbe180d92c6fdc57c48c494fe1"},
    {"0000000000000000000000000000000000000000000000000000000000000011", "03f584a358bfae57ad0b0c1b9bf5047a2bd4109314ede3b45906c546e861bdb98e428b6a"},
    {"0000000000000000000000000000000000000000000000000000000000000032", "017b807fb1b99265b3141cdd98e265723b60221ff9bfd2b1da8dc62d7dcef0466342c7a2"},
    {"000000000000000000000000000000000000000000000000000000000000000d", "008797f521f698df880c75938a63e7e675c611c565def71f7205c03545e7f4e38bd1db34"},
    {"0000000000000000000000000000000000000000000000000000000000000016", "07ee19dc6827f349ed2c60e436531d86a79615608579349aee81b216e6986ff2eb8979ef"},
    {"0000000000000000000000000000000000000000000000000000000000000011", "00f1e9d590c72462ec085c845e5126153ba00ecdcaf204ddad49d952ae5f3b57160fa3da"},
    {"000000000000000000000000000000000000000000000000000000000000001b", "07bb09d252458d77c408b4713cb171820ba00cbc48a7a4e2b1d567232797df337dd168b7"},
    {"0000000000000000000000000000000000000000000000000000000000000001", "099cd95933aaad7b9b37d020d6752e497f3c0e2989ada16662a1a63cec66d49695c62dba"},
    {"0000000000000000000000000000000000000000000000000000000000000054", "1a671dba23f7ad03672f289911e4ff398d9b1b3dd97724248ea5d448d9535437f40e336e"},
    {"0000000000000000000000000000000000000000000000000000000000000019", "034f554c604184189d1b39245e4329c0f1540fa39e57e1565345c115c1e5db842d9d938e"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "07db910fd224c4e9cc0a7d951a68c5269fc90f2a95d9e3ba3f4ff236cb6fde03e792d772"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "008dc8178114159d87064563f5620d7a61df141cec1b451ac30dfc1b749cd8842db9371d"},
    {"000000000000000000000000000000000000000000000000000000000000001b", "0ba01c95f2c7139fe95235ec5ed9067311d423264b66f30d49cfe127f45e7502e314ccdb"},
    {"000000000000000000000000000000000000000000000000000000000000001a", "15d2a4f3728e2520bb5938e4d416345f09fe2bdb50af7545fe0fe448f558ee46a79a131e"},
    {"000000000000000000000000000000000000000000000000000000000000004f", "02cb975720e47133c3109b14d4419f091ebe117b50eea62c51a5ae24660a5d3a76b739e5"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "062c094ba09b7ca4c10833613372ec1d37930a18a27c81340127a756782998b8a606b9a0"},
    {"0000000000000000000000000000000000000000000000000000000000000016", "09c7a234048c5e1bba46721ed7e5cd7e5b420a5687854204c0ac971f7a639d3557157116"},
    {"0000000000000000000000000000000000000000000000000000000000000001", "02361c5c9060c0bcd53f6956f5c8b65a4b8c213f9896b46d2219502d3211d7037d6100d1"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "01cc516e73bfb5b3140e794e8fb41cddc98805d3551e62673a178915eb6855f4eb5a2f60"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "036a4c7c41fe88d2731ed4a41da6bb9a7f5d0c16569056e386b3b90ee0472e054581e7c2"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "06980c757107997b4d19b8985b979cc6a96120da10f35383cadd7f67f023169b16bb75c6"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "02ee48d573751de73b1463c54513f7c9b95e09346dfb43069a79be10c06015918bffb3e3"},
    {"0000000000000000000000000000000000000000000000000000000000000013", "0befc7f642e26d198243d3de14977f3357e927c4ccfe861ca67fd832bf191fb3b74181d9"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "048beede57ddde01940a22ea58788c4f15f60c67e99df32c0500f0286d7a5f42e7b23d21"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "07bf89e9f0cf72d19814bba79ab522afabe12efc1caed7d7124fc236b258d6037abce587"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "002a2257c87d36c9e85bf4dd9187afc62d8e15784739029746492a2ed7b4ba7444ae4f3b"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "2065a47ab5751191ee20ae500f64d37e57bd29ca557c23b4c5aae93db6709a9743fe41bf"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "0144f75bf05680233021d7dd9764f2dad9b74afd1b1d5676b9c7b591d06fbec98fc765c9"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "011f911bd46acd850e0671b59b251cf381ca209f2f7959b5fb23c9527128d706a39ef3bb"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "031b477aa1cf268bc01ec109d11636e2e5d1256590b8f4a7092dd072665eb39da73783eb"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "0e39f6db758f21b9921818104c652aaf73d51eb44f36829fb6d3bf3b32af3cd6f69293e2"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "05f26213f1da0cea8124549bce5283ce37eb11d01cf764adad64f52e1f34bef6c4928bb3"},
    {"000000000000000000000000000000000000000000000000000000000000001e", "20d4ab99f90dc2f1ca2349895eb23cce2d3f3e641675a43635ff1e783e255fc9d5faafea"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "0868c4b3131668e1b8241db07a13647cf08f0a9dd52d51ce3966cc25da8f7aa7fca777fd"},
    {"000000000000000000000000000000000000000000000000000000000000001e", "0148b9dd12872319fe0479d7ba615d5c727b037183c5b2cfaf1ddb617dde579935deb9da"},
    {"000000000000000000000000000000000000000000000000000000000000001d", "0c7d33bd21ecae37c14c31172e8c2e3f21cc0d78cfdb73af58fb0a17f10cb553631925df"},
    {"000000000000000000000000000000000000000000000000000000000000001d", "0404183f338afecba80ea9856301b4fdcb1a06cd0d4d6405354aac41e92a7af71dbf03c2"},
    {"000000000000000000000000000000000000000000000000000000000000007b", "00de0fb9f68bfa958e0b42ae1b72b166b59c17cce8bd624ffe1f2233d451aaa38711b5e1"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "079207277237fe479e0c71d5db744c47a3dc239e1d6fb67ef6b7a33b4a8f99d62b33d1ea"},
    {"000000000000000000000000000000000000000000000000000000000000004e", "071ddad325ff825363207e0ff453c2eeb97c08bc8e8c2413de5bf90a1c062f35c4257b7f"},
    {"0000000000000000000000000000000000000000000000000000000000000000", "151a092751c2d683bb60f6df39ba87630dfb17c28ac5a29231592736e59bf3b496223b74"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "0332cb2b971c7359f320cbe29c2915c37ddf113de1f3344ab1b7ca3fff6136f886db0d8b"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "01d64efc84f5beb9c22e396dbf73d795e9a306c0d2df90f19e3dde143385a7655cf255c9"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "056b26794826da27a30b60de3c3522d79bf705a3d97a666d73b9f03ac7170f348b812cba"},
    {"0000000000000000000000000000000000000000000000000000000000000015", "00eee979b66bafaded064acc2f815564d7f101d903d92213de21510be2e1f1f3dac21950"},
    {"000000000000000000000000000000000000000000000000000000000000000f", "02c2415f660b92776106fe63fa90ae112cd4143bcf3f57fc07c3f2234a2111433a879bf8"},
    {"0000000000000000000000000000000000000000000000000000000000000020", "01c2c2e818a4dedd7e03cf8d704041504831027522d944038e07423a5b221607071ae7a1"},
    {"0000000000000000000000000000000000000000000000000000000000000029", "0345f73c72c450cdda43a6e6980457a1bf0f20e82abb42d4e4e2a32ccf9a7a1ac77ac1d6"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "15a1df51239f7af3c54c33da5697c506f9f623704bf9044a5593dc507af87fe88d36c3ed"},
    {"000000000000000000000000000000000000000000000000000000000000000e", "14d025fb22d78116ec395a189c54a6857aee2567ef5bd7af6a935e5779df37fb2663a7f9"},
    {"0000000000000000000000000000000000000000000000000000000000000017", "0a455a5aa4c271a92b20b0a5fc657e8e53971729ded5681d26335b4eda689b44fe114cb5"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "0b2bc3db721499695c2adf1e3c457559fbe00ddc103a90ef6d455d1347dd576955bb4bda"},
    {"0000000000000000000000000000000000000000000000000000000000000026", "0cf977fe19077e4f4d0d928decb4dfedc3e40ee1d52ee23488c278216f51f595c5f293ef"},
    {"000000000000000000000000000000000000000000000000000000000000000f", "10d1705c98e78eb35d125023f3a475dd3b7d25a2367c1405d591b229ad77dfc346918995"},
    {"0000000000000000000000000000000000000000000000000000000000000071", "00a350370b26cafd9541b1dd70e487917f3117ca5859c1f218eb503d74aeddf5bcd5bb9e"},
    {"0000000000000000000000000000000000000000000000000000000000000000", "0212f1be8443be513317f14648a66d8a6f491acc1bf033bbf3bbf456e7e89f759b7586ca"},
    {"0000000000000000000000000000000000000000000000000000000000000038", "005c93d33219510ed811c545ded4c2c21f131db71bdba2ae1395eb20f4127b834c21eb36"},
    {"0000000000000000000000000000000000000000000000000000000000000030", "0af548a5e5ebfaffc60d425cd7416cd91fe61522f9bd3312ace5d72ed4eb1873ae3d2097"},
    {"0000000000000000000000000000000000000000000000000000000000000056", "1d4ad12912da29f54b4745e41975e4da49702063ca18851e1fb1f443d6283ed7c5268b6e"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "00758730b092c055b401ef8e6c2033ea91a102ba1a922423bed5bb0e97555201292937ca"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "0661541090aef4434e282e1d3743b20a398211ce8adcd62fd9cbc046b6ed5779bf268fe8"},
    {"000000000000000000000000000000000000000000000000000000000000000d", "0b1b20d991e7549b584e4c22fc858e17079220bd225a729ed0db5a3435589b65156d8ecd"},
    {"0000000000000000000000000000000000000000000000000000000000000012", "072a1793d2af2addc2167d066481de8309b510f0dbbfc78e2e4f6d37f56bf6153f4f13b3"},
    {"000000000000000000000000000000000000000000000000000000000000004f", "058c475251b7374fed1c66327a52ed12d7b327a81471b30a7ea9d22e7c1a33632cdd436d"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "010b5e1f51bdf148ec28364ae7a57f46e5ce08b5d4ec5c3fff55dd0e8cd52fe38aa9977f"},
    {"000000000000000000000000000000000000000000000000000000000000000d", "001a962c709984b8bc114894f803ec6ab9840439c5d7f72e21fb5e0c49099101569d26d0"},
    {"000000000000000000000000000000000000000000000000000000000000005c", "0c7785dcf1236a11253d2d9391c54f8d5efc11c9ac59e255a5e3ce512f1d7055ef468193"},
    {"0000000000000000000000000000000000000000000000000000000000000000", "01a364594101d562ea2c7c8c09041789acee1bef16fd95aae27dc64dabab3b459665c5e8"},
    {"0000000000000000000000000000000000000000000000000000000000000008", "01408d2f18bc9323d60c581c39c39b3aa9e70f2a575643bb7d4b3e21330f1a84ebcbd9f2"},
    {"0000000000000000000000000000000000000000000000000000000000000048", "092b359cb34d1939b3339c0f71c5e7bf05c30ac07a3da23f5d179a4c69a09948347aede9"},
    {"0000000000000000000000000000000000000000000000000000000000000024", "150d5c9d1b65fadda823afdbfa0377e665ed1b168cfae2f2d566ee3054a292ba86debbea"},
    {"0000000000000000000000000000000000000000000000000000000000000029", "0692c455038499c7951ac926bc526a1e83c9096aa67a21b650ed961e96cbb58356f5f11a"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "005bb51be1fa6ebb743fa6279b14878e0fe901d6009d01bb3d7aca26fcd9b243bac90687"},
    {"0000000000000000000000000000000000000000000000000000000000000028", "0b2ef59c30c409d5a8156f4d156241859efb2767d6d3da763b2ba6394f30bf04bbb6f1fb"},
    {"0000000000000000000000000000000000000000000000000000000000000012", "04cbdecfe36205b7f43cb1501b659c1f73c406c9030890a5dafda02597ccbf655c817598"},
    {"0000000000000000000000000000000000000000000000000000000000000028", "0ac909ae00e3221db32ad0de55150369c9f90d0895cd512f2e97d4125a5814066cbe4588"},
    {"0000000000000000000000000000000000000000000000000000000000000000", "1d6c89a74f67bbebf9239bdd55b2452353fc27499f1c9afe2329a12d2958b4b736629fe3"},
    {"0000000000000000000000000000000000000000000000000000000000000039", "03274778521f894d110f5026b5c69f6e916111f0534e533d514ff3131d19f465eec735ac"},
    {"0000000000000000000000000000000000000000000000000000000000000019", "052842c63102b0569e1257d810e63559e14416374e48f814a759bd1b128a38925e6e17e9"},
    {"000000000000000000000000000000000000000000000000000000000000000e", "052cfdbee35e9eedca274823b3a3f53d7fe70d8da7bae57d0b59f93da526d4c674d5d1a6"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "001496bd42321a7d7a1c5c0945b4d4b6cff51dcdfc3ee25e65758a30c8abdb650dfdf76c"},
    {"000000000000000000000000000000000000000000000000000000000000000d", "00f0f51ec2b5be3fb50ce4a616c0d8e0caaa0b68599b919c66b58422128b15b5e39b59e5"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "04201490219ab8bc94187b5edf4495dd85390ee7c5896341a71bc529c9679ff2e4f4d7f1"},
    {"0000000000000000000000000000000000000000000000000000000000000030", "0131e19521de20886318d54f9921f44d6f380c73201a069d6755ed2b7775def6e609cd01"},
    {"000000000000000000000000000000000000000000000000000000000000001d", "0328d49e26d685d9d10514a27183cad15cc11cac07717301f9cdf82b729d1229e7d6bbe8"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "01e562521020943bfc15ade23be1d3d93b0a0bdcab5752d411349e5931e17909059b158f"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "08be4aead1fb023f4244c9251b261725b0dd0ee9329dd4b3adfd791e256957022ad9a30d"},
    {"000000000000000000000000000000000000000000000000000000000000001b", "031a15aea32b391cec2c5f15f803cf12131a12305770027dc5fddf1f7e28f7221d56b5f7"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "06e520fea183a174f4223615ceb767ce99f808308c1ce25db171483c4d6f1e649d1e49c9"},
    {"0000000000000000000000000000000000000000000000000000000000000011", "2e66f21ea50fbd66fc3772d76da5ac8ecbce3199a71ae47b99eb133aa35653c3b7d32bcd"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "00284b1277ce7e3baa1548753ad2ab562f36026c187d30af3261f3140f6a7cb222c4d2cc"},
};

static CBlockIndex CreateBlockIndex(int nHeight) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = ::ChainActive().Tip();
    return index;
}

static bool TestSequenceLocks(const CTransaction &tx, int flags) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    LOCK(::mempool.cs);
    return CheckSequenceLocks(::mempool, tx, flags);
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
static void TestPackageSelection(const CChainParams& chainparams, const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(cs_main, ::mempool.cs)
{
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL - 1000;
    // This tx has a low fee: 1000 satoshis
    uint256 hashParentTx = tx.GetHash(); // save this txid for later use
    mempool.addUnchecked(entry.Fee(1000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = 5000000000LL - 10000;
    uint256 hashMediumFeeTx = tx.GetHash();
    mempool.addUnchecked(entry.Fee(10000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 50k satoshi fee
    uint256 hashHighFeeTx = tx.GetHash();
    mempool.addUnchecked(entry.Fee(50000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetHash() == hashParentTx);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetHash() == hashHighFeeTx);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetHash() == hashMediumFeeTx);

    // Test that a package below the block min tx fee doesn't get included
    tx.vin[0].prevout.hash = hashHighFeeTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 0 fee
    uint256 hashFreeTx = tx.GetHash();
    mempool.addUnchecked(entry.Fee(0).FromTx(tx));
    size_t freeTxSize = ::GetSerializeSize(tx, PROTOCOL_VERSION);

    // Calculate a fee on child transaction that will put the package just
    // below the block min tx fee (assuming 1 child tx of the same size).
    CAmount feeToUse = blockMinFeeRate.GetFee(2*freeTxSize) - 1;

    tx.vin[0].prevout.hash = hashFreeTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000 - feeToUse;
    uint256 hashLowFeeTx = tx.GetHash();
    mempool.addUnchecked(entry.Fee(feeToUse).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    // Verify that the free tx and the low fee tx didn't get selected
    for (size_t i=0; i<pblocktemplate->block.vtx.size(); ++i) {
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashFreeTx);
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashLowFeeTx);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee
    // Remove the low fee transaction and replace with a higher fee transaction
    mempool.removeRecursive(CTransaction(tx), MemPoolRemovalReason::REPLACED);
    tx.vout[0].nValue -= 2; // Now we should be just over the min relay fee
    hashLowFeeTx = tx.GetHash();
    mempool.addUnchecked(entry.Fee(feeToUse+2).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate->block.vtx[4]->GetHash() == hashFreeTx);
    BOOST_CHECK(pblocktemplate->block.vtx[5]->GetHash() == hashLowFeeTx);

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block.
    // Add a 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout.resize(2);
    tx.vout[0].nValue = 5000000000LL - 100000000;
    tx.vout[1].nValue = 100000000; // 1LTZ output
    uint256 hashFreeTx2 = tx.GetHash();
    mempool.addUnchecked(entry.Fee(0).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself
    tx.vin[0].prevout.hash = hashFreeTx2;
    tx.vout.resize(1);
    feeToUse = blockMinFeeRate.GetFee(freeTxSize);
    tx.vout[0].nValue = 5000000000LL - 100000000 - feeToUse;
    uint256 hashLowFeeTx2 = tx.GetHash();
    mempool.addUnchecked(entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);

    // Verify that this tx isn't selected.
    for (size_t i=0; i<pblocktemplate->block.vtx.size(); ++i) {
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashFreeTx2);
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashLowFeeTx2);
    }

    // This tx will be mineable, and should cause hashLowFeeTx2 to be selected
    // as well.
    tx.vin[0].prevout.n = 1;
    tx.vout[0].nValue = 100000000 - 10000; // 10k satoshi fee
    mempool.addUnchecked(entry.Fee(10000).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate->block.vtx[8]->GetHash() == hashLowFeeTx2);
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    // Note that by default, these tests run with size accounting enabled.
    const auto chainParams = CreateChainParams(CBaseChainParams::REGTEST);

    const CChainParams& chainparams = *chainParams;
    CScript scriptPubKey = CScript() << ParseHex("04aaa049f7609d4b17ac733a67dd8abd10c0b5b410f0b3681b36dfb85fdc157fa22257895785bfc0c8741a9ff87d98d8a9a5330a8790aadd2f709576f65b37db89") << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    CMutableTransaction tx;
    CScript script;
    uint256 hash;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.nHeight = 11;

    fCheckpointsEnabled = false;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // We can't make transactions until we have inputs
    // Therefore, load 100 blocks :)
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (unsigned int i = 0; i < sizeof(blockinfo)/sizeof(*blockinfo); ++i)
    {
        CBlock *pblock = &pblocktemplate->block; // pointer for convenience
        {
            LOCK(cs_main);
            pblock->nVersion = 4;
            pblock->nTime = ::ChainActive().Tip()->GetMedianTimePast()+6*Params().GetConsensus().nPowTargetSpacing;
            CMutableTransaction txCoinbase(*pblock->vtx[0]);
            txCoinbase.nVersion = 1;
            txCoinbase.vin[0].scriptSig = CScript() << (::ChainActive().Tip()->nHeight+1) << OP_0;
            txCoinbase.vout[0].scriptPubKey = CScript();
            pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
            if (txFirst.size() == 0)
                baseheight = ::ChainActive().Height();
            if (txFirst.size() < 4)
                txFirst.push_back(pblock->vtx[0]);
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->nNonce = uint256S(blockinfo[i].nonce_hex);
            pblock->nSolution = ParseHex(blockinfo[i].solution_hex);
            // These tests assume null hashSaplingRoot (before Sapling)
            pblock->hashSaplingRoot = uint256();
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        BOOST_CHECK(ProcessNewBlock(chainparams, shared_pblock, true, nullptr));
        pblock->hashPrevBlock = pblock->GetHash();
    }

    LOCK(cs_main);
    LOCK(::mempool.cs);

    // Just to make sure we can still make simple blocks
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    const CAmount BLOCKSUBSIDY = 50*COIN;
    const CAmount LOWFEE = CENT;
    const CAmount HIGHFEE = COIN;
    const CAmount HIGHERFEE = 4*COIN;

    // block sigops > limit: 1000 CHECKMULTISIG + 1
    tx.vin.resize(1);
    // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY;
    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        bool spendsCoinbase = i == 0; // only first tx spends coinbase
        // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
        mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }

    BOOST_CHECK_EXCEPTION(AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-blk-sigops"));
    mempool.clear();

    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vout[0].nValue = BLOCKSUBSIDY;
    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        bool spendsCoinbase = i == 0; // only first tx spends coinbase
        // If we do set the # of sig ops in the CTxMemPoolEntry, template creation passes
        mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(spendsCoinbase).SigOpsCost(80).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    mempool.clear();

    // block size > limit
    tx.vin[0].scriptSig = CScript();
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<unsigned char> vchData(520);
    for (unsigned int i = 0; i < 18; ++i)
        tx.vin[0].scriptSig << vchData << OP_DROP;
    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vout[0].nValue = BLOCKSUBSIDY;
    for (unsigned int i = 0; i < 128; ++i)
    {
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        bool spendsCoinbase = i == 0; // only first tx spends coinbase
        mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    mempool.clear();

    // orphan in mempool, template creation fails
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    mempool.clear();

    // child with higher feerate than parent
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = BLOCKSUBSIDY-HIGHFEE;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout.hash = txFirst[0]->GetHash();
    tx.vin[1].prevout.n = 0;
    tx.vout[0].nValue = tx.vout[0].nValue+BLOCKSUBSIDY-HIGHERFEE; //First txn output + fresh coinbase - new txn fee
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(HIGHERFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    mempool.clear();

    // coinbase in mempool, template creation fails
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = 0;
    hash = tx.GetHash();
    // give it a fee so it'll get mined
    mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw bad-cb-multiple
    BOOST_CHECK_EXCEPTION(AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-cb-multiple"));
    mempool.clear();

    // double spend txn pair in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = BLOCKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_EXCEPTION(AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    mempool.clear();

    // subsidy changing
    int nHeight = ::ChainActive().Height();
    // Create an actual 839999-long block chain (without valid blocks).
    while (::ChainActive().Tip()->nHeight < 839999) {
        CBlockIndex* prev = ::ChainActive().Tip();
        CBlockIndex* next = new CBlockIndex();
        next->phashBlock = new uint256(InsecureRand256());
        ::ChainstateActive().CoinsTip().SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    // Extend to a 840000-long block chain.
    while (::ChainActive().Tip()->nHeight < 840000) {
        CBlockIndex* prev = ::ChainActive().Tip();
        CBlockIndex* next = new CBlockIndex();
        next->phashBlock = new uint256(InsecureRand256());
        ::ChainstateActive().CoinsTip().SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = BLOCKSUBSIDY-LOWFEE;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(script));
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(script.begin(), script.end());
    tx.vout[0].nValue -= LOWFEE;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw block-validation-failed
    BOOST_CHECK_EXCEPTION(AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("block-validation-failed"));
    mempool.clear();

    // Delete the dummy blocks again.
    while (::ChainActive().Tip()->nHeight > nHeight) {
        CBlockIndex* del = ::ChainActive().Tip();
        ::ChainActive().SetTip(del->pprev);
        ::ChainstateActive().CoinsTip().SetBestBlock(del->pprev->GetBlockHash());
        delete del->phashBlock;
        delete del;
    }

    // non-final txs in mempool
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast()+1);
    int flags = LOCKTIME_VERIFY_SEQUENCE|LOCKTIME_MEDIAN_TIME_PAST;
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].nSequence = ::ChainActive().Tip()->nHeight + 1; // txFirst[0] is the 2nd block
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(CheckFinalTx(CTransaction(tx), flags)); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks fail
    BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, &prevheights, CreateBlockIndex(::ChainActive().Tip()->nHeight + 2))); // Sequence locks pass on 2nd block

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (((::ChainActive().Tip()->GetMedianTimePast()+1-::ChainActive()[1]->GetMedianTimePast()) >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) + 1); // txFirst[1] is the 3rd block
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(CheckFinalTx(CTransaction(tx), flags)); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks fail

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        ::ChainActive().Tip()->GetAncestor(::ChainActive().Tip()->nHeight - i)->nTime += 512; //Trick the MedianTimePast
    BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, &prevheights, CreateBlockIndex(::ChainActive().Tip()->nHeight + 1))); // Sequence locks pass 512 seconds later
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        ::ChainActive().Tip()->GetAncestor(::ChainActive().Tip()->nHeight - i)->nTime -= 512; //undo tricked MTP

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = ::ChainActive().Tip()->nHeight + 1;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(CTransaction(tx), flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), ::ChainActive().Tip()->nHeight + 2, ::ChainActive().Tip()->GetMedianTimePast())); // Locktime passes on 2nd block

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = ::ChainActive().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(CTransaction(tx), flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), ::ChainActive().Tip()->nHeight + 2, ::ChainActive().Tip()->GetMedianTimePast() + 1)); // Locktime passes 1 second later

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = ::ChainActive().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTx(CTransaction(tx), flags)); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags)); // Sequence locks fail

    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // None of the of the absolute height/time locked tx should have made
    // it into the template because we still check IsFinalTx in CreateNewBlock,
    // but relative locked txs will if inconsistently added to mempool.
    // For now these will still generate a valid template until BIP68 soft fork
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 3U);
    // However if we advance height by 1 and time by 512, all of them should be mined
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        ::ChainActive().Tip()->GetAncestor(::ChainActive().Tip()->nHeight - i)->nTime += 512; //Trick the MedianTimePast
    ::ChainActive().Tip()->nHeight++;
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast() + 1);

    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5U);

    ::ChainActive().Tip()->nHeight--;
    SetMockTime(0);
    mempool.clear();

    TestPackageSelection(chainparams, scriptPubKey, txFirst);

    fCheckpointsEnabled = true;
}

BOOST_AUTO_TEST_SUITE_END()
