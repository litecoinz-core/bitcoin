// Copyright (c) 2011-2019 The Bitcoin Core developers
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
    {"0000000000000000000000000000000000000000000000000000000000000006", "0df7a293e181dddd530e2ccc2662bebcfca40e929d14019cddb31d47fb6e7967cdd62d56"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "037ee779825b964fe30a4d487a557ebf53e410d5cc3e53ea3a0b1f2caa58fe635cf92bb8"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "1768cd2a5212c0f1be2c18dd2fc8dfca5f405f7aae5fc7572f17b185fe6fbcf9c69f43bb"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "09d0c4c3f4a5968dc533e497377494795bb2164b32bdd89667abeb3764dc927776e9f775"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "1042f07d81d19e1ba929e7a919c48cca896e1297f6bd13d62141981e626ebf727d04ab8b"},
    {"0000000000000000000000000000000000000000000000000000000000000012", "09bd0e09f312066f5441c01e3bd6658d9b850c31dfbdc8b73aaf5f1310e091023c7b03ab"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "0e3fa29b7100a23d37173fc88842419d033e14f5d6bc819b8a418f5060b15a753aabaddc"},
    {"000000000000000000000000000000000000000000000000000000000000002b", "26298f76a3576aa95f2ff315f4b5aaef0f882de754b254ba758dd6336124d933ee5d3f0f"},
    {"0000000000000000000000000000000000000000000000000000000000000030", "09982d5e10ae94917e17380999834a4ee38e138a0da9515535f3402a58de5356be85c7ef"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "006c4e2a20f91ba7f911ea1c5fe7c412b3bb15d2db7a677ccf07941a37d3d3f9af2275f2"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "00d1ab5d70a7bce89904f3d432e148f524ad405f15d92a9dbb3dfd63c3a2ff867ed9c5b2"},
    {"0000000000000000000000000000000000000000000000000000000000000013", "04254efb423a7dfd92066c657ec6579ad57d122bdc3d01848ca0fb4efe277e285c563554"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "0ede50d9eb2dcf41f8517ed74c38166f239d15a6e81641ccfceead2edacedde3c665b71b"},
    {"0000000000000000000000000000000000000000000000000000000000000013", "014b045eb35dcce4730c398fb797af061f960238ec3dc1d170ddd70812ccfe45331721e9"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "05fc247ec8c5ee3f4c0b2f49d8830c3b4bcf17c51bbe7422e16fb2455a9d71a816d6fbda"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "0c38747e61f7d6e7b316469670c1ab8c8b982741e013a51c65af0e2cf51fd4263b959d92"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "1f7b4b72bb2e53a1d340559c3e56260aa17330a864bdd53b467f476a4a2376a8a5eef3fe"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "0164c848224dfe939102359617a383d16dbc050f22fcb6357dede75566958fd98fa3e9f7"},
    {"0000000000000000000000000000000000000000000000000000000000000008", "055f64d6613555c1410effc65504f6c3159705d865d3328dd225702fc0e0bf340e020d65"},
    {"0000000000000000000000000000000000000000000000000000000000000024", "0544207c812b74888105c94413759e770fec245690d786a61a856c4f72f0bc9517a150ca"},
    {"0000000000000000000000000000000000000000000000000000000000000010", "0b73c346fb3622cfd12b1fa35798a7a2a97e25589e1ee946efaddd47f99c7ad6def38def"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "056f45e873cc94f9aa45f5f4df9ad74b4fca0a3c8e7e927b89b3821256cbd363042ecdde"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "00ddc0a2e20e899be70e7952b6c324512d4514f82af5e19771f58315b1d1dcc26378cf19"},
    {"000000000000000000000000000000000000000000000000000000000000000d", "02bdc29d33bc7145d5283f8a94b4437229d02595a5bc593d52e7ba2c9e1f12961e1df5db"},
    {"0000000000000000000000000000000000000000000000000000000000000011", "1062197514bfe9bd5448eb95d434c3adc527172e09b462b2490d7a1fef26fd25ac79f3ce"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "0395b45a91c488e8f614395499e35a597f580ef4b29c916f7d89575df8ad99369e71a92f"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "0f6e54da169e9aa5cc20e393ce35454159092f64b87dd596c66f484a30d6b4673d123988"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "069f5492111f8f49fa1024aaf894ba8a01e70d07cc323188f8b53412391c3351bead53eb"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "0966383e889e324bc010ca97dee25bded5e7157eeffbd847b269cf1df3bb7f383d3ec563"},
    {"000000000000000000000000000000000000000000000000000000000000000f", "0a3e8f69423e3e937053ce5dbd759dd2cdea1eb908b9e3769679644d311bf34645fa25c7"},
    {"000000000000000000000000000000000000000000000000000000000000000e", "055d4596e113257d460fb45299e2ee392bc30dc1f11b553d1d65d216ba0767d6fe2a3bac"},
    {"0000000000000000000000000000000000000000000000000000000000000001", "10b186d7a4159975c01bbbdddeb5156dc9711625b53ed3c385efdb2ca251ee9396e23f79"},
    {"0000000000000000000000000000000000000000000000000000000000000001", "00d38652a28c2b2da30a338576d382edf31501855f939645ddeb3b0ffa60dee1b1ec97fb"},
    {"000000000000000000000000000000000000000000000000000000000000001f", "01b1161b01c7d591fa1547783e548615dfa0046595cc25645639e8112ac62f5192247fed"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "0227c1ab14b4d58bab125f5bce063cff33be23ab9a7705a41239413ef2121ed3f23d6719"},
    {"0000000000000000000000000000000000000000000000000000000000000028", "00d12e1cf94d1717e623794c2f16d7e335ab09ef0dbc220ab8e0a521b766bd54b7f95b20"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "09c67e3fb60cc28f83124d15cdb166f50ce111244d6a1284a2ff944b3318f864fbc1512d"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "060d85a2e4aade73eb103aa876727cdea3e7068fcbda8aa56ab3c511335a8d7211d086e7"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "03158fede3920a5dcc222452b5a4be5155400a6ac6ed961e0791fa39e158fc33ea22c38e"},
    {"0000000000000000000000000000000000000000000000000000000000000029", "0d3e987f43e5b593160e468c3931336911f30dc269de6167a2b7b7140fa53684233687ff"},
    {"000000000000000000000000000000000000000000000000000000000000002b", "0271e7ff253f796dd80beceb5f54b3fa6f5415d499d4833a3d5ddd28cace5df2ea64f4aa"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "0190991f21da1259b80d74e956e7f4d77fcb044ed9f391229529ad20ff4bcb651e82079b"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "0262d15ba2abe14dc608bb953a344d2930ce1fd070bd026d256b312ca2d6d753be6a8b90"},
    {"000000000000000000000000000000000000000000000000000000000000002f", "04d3a45b8089d440f118f98f6bf463315b660730c65473bbea7fde0f259639b1bd651143"},
    {"0000000000000000000000000000000000000000000000000000000000000018", "009cdeb7d50d41efb80eddd62ea40cf97dbc0e2f54558134f4f77821b5c8c5d4be63b5e0"},
    {"0000000000000000000000000000000000000000000000000000000000000012", "135ba2df3532a1a5ad4f2e9adac5bc19e9021455457bb45c6a57613de51612372d2e81b0"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "05ea9c17e3e2b573321553933e426c58f7f20ac4d69f720d5cbd7b23e3d04cca6e729f58"},
    {"000000000000000000000000000000000000000000000000000000000000001d", "0197930ce59adb39a116e14a0ed199651b9305d3de92e81e5e7ba2625798eff96e1325af"},
    {"0000000000000000000000000000000000000000000000000000000000000001", "0979d25e650d9b33d91c9f269a04a7c671e4105490afd44b6d1cb11e2e497911f2016beb"},
    {"000000000000000000000000000000000000000000000000000000000000001d", "0425c4abf0b7593bdc47aba2da27a69e4b4110fb144fa2abfd63f73eb85e7de52bba7b66"},
    {"0000000000000000000000000000000000000000000000000000000000000027", "016ac16a706521239401a704ca35b412152504e36416810141650809be0bfdc6c615b6e3"},
    {"000000000000000000000000000000000000000000000000000000000000000f", "0202a99884b4616b1619748d138b6e6b2dad252d999d84759f45db5f59a37c2856ef0d9b"},
    {"0000000000000000000000000000000000000000000000000000000000000012", "039b855dd402c71dac494d265fe4c65a8b4e23dc519373060d5310299da099f37e362dea"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "01d1609b00e49ea97c63b9a51db73eea2db40d359aee511a1dbb9e33a7a038145635ebd4"},
    {"0000000000000000000000000000000000000000000000000000000000000024", "0eaf5e7bf66e36479f20918dc8a2ecccebe11f6252de45d4f1a5ed5234d71846e41deb5d"},
    {"0000000000000000000000000000000000000000000000000000000000000018", "117b15ecb2b7411f9e4bff321ba6e655c1e011ea685a13873173913053ef1a330ebe275a"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "032b1e72909fb5218e1bcdd6bb146e35cd9311e6cdf9d1d7a643fc51e2ac39766d7a7def"},
    {"0000000000000000000000000000000000000000000000000000000000000015", "01b9cdb5488f0e33a855c29f17b733adf3910ef3d78f2535166be325391c6f62fd426951"},
    {"000000000000000000000000000000000000000000000000000000000000001c", "07cfdfd67084893b7819a188fff55f5ae9840f1a67d60976426d99375eda789905aeabd7"},
    {"0000000000000000000000000000000000000000000000000000000000000045", "03f28b5522056d1bc50d38d656c51f497d361aedd01b24ccfdcfa866da9e10b92d7f1ff0"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "0f3ae7bfb192ec684c1e8fe95e954b2727f41655527b54977a8d7d20ccc891530d6df5a0"},
    {"000000000000000000000000000000000000000000000000000000000000002e", "0c3be79c257eb9bd9f22aeaa3f52c58b7dfb1612aafa626c84df451929dabca986e2a99d"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "0c4e0487048b61c5b8242a1657f7867e8b8f1139c6a6763be9db2c22f14f19632296d5b6"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "016d1835213e7dc9f91e2460f5e77caa2d3713180724e30b4a4dd556f2659e59e75a97ad"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "087485e9e219b928ba0b510bb002e5570b98094c426a7331d1679a27d6b0fd85dd6e172e"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "0d24ddda01443964f215175799c2996a313d29669954aa1d5757ec2e1f621ca51ac2e592"},
    {"0000000000000000000000000000000000000000000000000000000000000014", "0a8a93edc58b09a0ee6c5722b3d9b69705d810ff44d61179cc93e02bca199ff3f449c7ee"},
    {"0000000000000000000000000000000000000000000000000000000000000021", "020280c7c26ebd7ba12d6c934f12d9d5539002fc749b62ad1148c51579dfbd28955a3d6f"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "08da8985aa2e96c1a912a85b75d60f6589e616e88a34040672218a18954767d34288d9c3"},
    {"000000000000000000000000000000000000000000000000000000000000001d", "0daf2b3d81e2be19e3246f10bda89f9ab178111329dad14e64850352bde1ff09367255ab"},
    {"000000000000000000000000000000000000000000000000000000000000005a", "0bbc0d4af48f1d77934570d4da9605963dea1dee163962b258cbc56e79255a175c6e0981"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "03070d4fd0c4171b963ec79c2e83ff8b47e5073d8f5c6117557b9b31c5d57b86c4b2bd9c"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "159ed0f1c617e6e9b62a6a18bbd664f9a6ea19e415da630a58d35235cd912a646415cf10"},
    {"0000000000000000000000000000000000000000000000000000000000000022", "08a9d95541289ef78e315ccc9105df72a3bf23afcd6b651531635846db6cde67973acb81"},
    {"000000000000000000000000000000000000000000000000000000000000006e", "032d0ae640ff9c8f9f0a6f459b51a6067f9b0f5a9eb6937ea14ba05e503c7fa6852205eb"},
    {"0000000000000000000000000000000000000000000000000000000000000016", "1d38d6343305fcdba45b6f255ab7ebfb65dc2091225f164b9b7ffe52b1dc16370bbdd98e"},
    {"0000000000000000000000000000000000000000000000000000000000000010", "017622b8862bf65dbf154374baf56f7d89c90fa245127805ae277a15985357067b6e0b6c"},
    {"0000000000000000000000000000000000000000000000000000000000000052", "05db0b3251be394ed2394e9b3c63a2a291b30ad055b5e273d8d86f1b5cd7f1e31194d561"},
    {"000000000000000000000000000000000000000000000000000000000000005c", "01a64ea7f177c24141050b4e4926f52703e10da0f65e77de6f2dc131c0f79be965635fc6"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "05f5e1999396ede9b11fd8559512fa365b7e164b1bbd3656e6afe04657d97086ffc2c1cf"},
    {"0000000000000000000000000000000000000000000000000000000000000017", "050587dc4227eaf18c192cd9cdc36be8ed3b10f39470b18e86014e20794e52452d859fe1"},
    {"000000000000000000000000000000000000000000000000000000000000005e", "04a883b2348a9dbd3f1c508948b2aec921ba0f655857a4359373d4316c1831f673828fb8"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "05c5876e23928f69cb0ee8643f71652ba5ff138d0f3c41c1a08f3715e58abed5f3a35fe4"},
    {"0000000000000000000000000000000000000000000000000000000000000033", "016413f3f2fb1cf5750808609c92626a05df226cd7958377ea71613921dacdf44d8928fe"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "0420cb9b00f24100a606a2464c9417028fd30c4ac5ddb3a4b6593021444c2e92353895df"},
    {"0000000000000000000000000000000000000000000000000000000000000055", "06fbc9fb009ada656b40f4dc75350e928fe011d13d5ec1c9918f101a7b534a85ddd5bdce"},
    {"0000000000000000000000000000000000000000000000000000000000000003", "1b61a8db73863e1b7e2fefd74cdaddd3d5fa1cd2878e721941e323527d27f9988e02879a"},
    {"000000000000000000000000000000000000000000000000000000000000001a", "08c231fe9247bd376a2653da92f2cd9965c125608dffd2bf0f4df958cf27df0614edc6f5"},
    {"000000000000000000000000000000000000000000000000000000000000005d", "0e39933233d456b1db155dd05997772e67731c659b7c4447e1217628ecefdee3a2edd792"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "0cc34e47e51dd96b961c970ecde53b29bb8a194a6654d7e64a71c056eeac1b477c7a59c3"},
    {"0000000000000000000000000000000000000000000000000000000000000010", "08c4424f76ecce3d7c1c4cb13b61cae8f545177e5af7d343cfabea635ae7b7975c4ea9f2"},
    {"000000000000000000000000000000000000000000000000000000000000000f", "0f8fd85ab13154d8952de05c7573abc90cbd138d5b3a01f61797d43039d037f31b39732d"},
    {"0000000000000000000000000000000000000000000000000000000000000015", "037d8edcb21ddd45a10f7718db988dce73470579debef8ff02c77d0657446bb32ac0e9bf"},
    {"0000000000000000000000000000000000000000000000000000000000000030", "0057413e412f673fee1ba90c1c2704f1cf5b0155e49f43a32a2fe058d5697a293e969bbf"},
    {"0000000000000000000000000000000000000000000000000000000000000002", "09b44bb9f0ff1cfd0d0f14e37b777ec755eb121c882dc69f9ac9b05355580eb66bd24fd9"},
    {"000000000000000000000000000000000000000000000000000000000000000e", "156f594e2374c9e9a336470fec767e0debbe1b45613f42767f2bba24cd931d447cd17985"},
    {"000000000000000000000000000000000000000000000000000000000000001c", "073a9d7cc171c884571fa38a6b98660b35fc2b4df81f63f35679424cd3abd9d56f71f2fe"},
    {"000000000000000000000000000000000000000000000000000000000000000a", "0158cbd4751faaebd9082303c5219244bed006e3d3b1b2db11ebcb15d6b79fe95f5ebdfa"},
    {"0000000000000000000000000000000000000000000000000000000000000035", "0110221457bd0e43fc1646ce67f3331ef7f923799f53a384da315f3731bc3f45ac35a1cd"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "13ba3a0a562dabeb82e19a49bd1bcca0f918a067116691d487c53bfec35d6601581c14f9bd21e240b84fe8bf8c7fc316c3b1c5229d74838fc6e888d69c353a9afa9df4c9"},
    {"0000000000000000000000000000000000000000000000000000000000000025", "0793fd75f21b9c5c04262a730f6445cae122ca1c541a2b3a83535d3e68163d5342c60b83bd4fcdaf1485d179fc1e614689bb5842e3759c53b653f3757a837a39638cb8f3"},
    {"0000000000000000000000000000000000000000000000000000000000000007", "05d6c3ad927c955753816e03f1c3a714c717908f4dc9b5748e228c5539f11ab2f1e9086890296158d418d2ce3d3e790d7adf151e176cbccfff4dc2d41b457d5f00bf80c7"},
    {"0000000000000000000000000000000000000000000000000000000000000009", "0805986e931ade48c5e6e5e1ddb6277a782bd52fbf15cefea456dfc4f62e0ac3ee284314788dd8c79de794501b4d2654ddfdcf4ccc7bee93eb5c56b64a0e1f076db1d865"},
    {"0000000000000000000000000000000000000000000000000000000000000004", "0403cddcc23c69a831299dfa4d9ab174c80833d5f64405be9750c49129bd94c930b00adbcaafc5f4e8ffb4d655599d7139c71c3bda75d35518da5164815372d57c299cd9"},
    {"000000000000000000000000000000000000000000000000000000000000000b", "0a39b755d2630c9129cfb51bdb90abdb9d1884a4de9ba3f7b183fa1c70920703ea841377171420019d7bb29b0e21ed47bd6b16499ad1961f0fb42fd7e77539eb9547fd5c"},
    {"0000000000000000000000000000000000000000000000000000000000000006", "04b0580dc93dca66109d3a1e344f3ac0715f714b19deef9e3c493c9fb462a565cbc9119bf27a6a1ed991724d7db2920767780652fd32d258b1ce1ab56a2b22efee41fb5a"},
    {"0000000000000000000000000000000000000000000000000000000000000005", "15dcf3052d947917f4dc8a8f82b9116ea7250cf6399c4774ec9519c4f49e3b17c72917c35cff4db05afc4246beab0ee33b953d19abde8f2e7f19f803c89ae8e19c08d6a9"},
    {"0000000000000000000000000000000000000000000000000000000000000001", "12b54ffdd5339141f345c2152d7676d4551882a77f87e8364a23a6fdfe311faf784c3a46536b1d0b563e65c3dde37677c1dee241d2fb42b7ee1f159763856c17a679d50c"},
    {"000000000000000000000000000000000000000000000000000000000000000e", "125dd50da70518a9136e67ed8bb9a3ebc830199b941cf01bdd78cb553b5b2c9dbed51ca237564ad68bbdf2ed973d0127ace4a15f3e4e1965805c4177d8d61026e519faf3"},
    {"000000000000000000000000000000000000000000000000000000000000000c", "03e712649d5a2eeef56bce4601844310bc18da669a8d375d7b834524125b5ba9e1e5058afa64cb768f2e70717637ff899bd3578759cf4aedb3da70fdab2f3efb9f59dfd3"},
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
    fCoinbaseEnforcedShieldingEnabled = false;

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
    fCoinbaseEnforcedShieldingEnabled = true;
}

BOOST_AUTO_TEST_SUITE_END()
