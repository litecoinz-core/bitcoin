// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <crypto/equihash.h>
#include <key_io.h>
#include <miner.h>
#include <outputtype.h>
#include <pow.h>
#include <script/standard.h>
#include <validation.h>
#include <validationinterface.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif

const std::string ADDRESS_BCRT1_UNSPENDABLE = "rltz1qkd88ytgqssu37rpaf0q7yuw7e030rh50xm8mg3ncqd7vqhzzcfpqr0hqs5";

#ifdef ENABLE_WALLET
std::string getnewaddress(CWallet& w)
{
    constexpr auto output_type = OutputType::BECH32;
    CTxDestination dest;
    std::string error;
    if (!w.GetNewDestination(output_type, "", dest, error)) assert(false);

    return EncodeDestination(dest);
}

void importaddress(CWallet& wallet, const std::string& address)
{
    LOCK(wallet.cs_wallet);
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    const auto script = GetScriptForDestination(dest);
    wallet.MarkDirty();
    assert(!wallet.HaveWatchOnly(script));
    if (!wallet.AddWatchOnly(script, 0 /* nCreateTime */)) assert(false);
    wallet.SetAddressBook(dest, /* label */ "", "receive");
}
#endif // ENABLE_WALLET

CTxIn generatetoaddress(const std::string& address)
{
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    const auto coinbase_script = GetScriptForDestination(dest);

    return MineBlock(coinbase_script);
}

CTxIn MineBlock(const CScript& coinbase_scriptPubKey)
{
    const CChainParams& chainparams = Params();

    static const int nInnerLoopCount = 0xFFFF;
    static const int nInnerLoopMask = 0xFFFF;
    uint64_t nMaxTries = 1000000;

    unsigned n = chainparams.GetConsensus().EquihashN(::ChainActive().Tip()->nHeight + 1);
    unsigned k = chainparams.GetConsensus().EquihashK(::ChainActive().Tip()->nHeight + 1);

    auto block = PrepareBlock(coinbase_scriptPubKey);

    crypto_generichash_blake2b_state eh_state;
    EhInitialiseState(n, k, eh_state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*block};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;

    // H(I||...
    crypto_generichash_blake2b_update(&eh_state, (unsigned char*)&ss[0], ss.size());

    while (nMaxTries > 0 && ((int)block->nNonce.GetUint64(0) & nInnerLoopMask) < nInnerLoopCount) {
        // Yes, there is a chance every nonce could fail to satisfy the -regtest
        // target -- 1 in 2^(2^256). That ain't gonna happen
        block->nNonce = ArithToUint256(UintToArith256(block->nNonce) + 1);

        // H(I||V||...
        crypto_generichash_blake2b_state curr_state;
        curr_state = eh_state;
        crypto_generichash_blake2b_update(&curr_state, block->nNonce.begin(), block->nNonce.size());

        // (x_1, x_2, ...) = A(I, V, n, k)
        std::function<bool(std::vector<unsigned char>)> validBlock =
                [&block](std::vector<unsigned char> soln) {
            block->nSolution = soln;
            return CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus());
        };
        bool found = EhBasicSolveUncancellable(n, k, curr_state, validBlock);
        --nMaxTries;
        if (found) {
            break;
        }
    }

    bool processed{ProcessNewBlock(Params(), block, true, nullptr)};
    assert(processed);

    return CTxIn{block->vtx[0]->GetHash(), 0};
}

std::shared_ptr<CBlock> PrepareBlock(const CScript& coinbase_scriptPubKey)
{
    auto block = std::make_shared<CBlock>(
        BlockAssembler{Params()}
            .CreateNewBlock(coinbase_scriptPubKey)
            ->block);

    LOCK(cs_main);
    block->nTime = ::ChainActive().Tip()->GetMedianTimePast() + 1;
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    return block;
}
