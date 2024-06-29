// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <crypto/equihash.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <util/system.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    int nHeight = pindexLast->nHeight + 1;

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    if (nHeight < params.nLegacyLwmaForkHeight)
        return DigishieldGetNextWorkRequired(pindexLast, pblock, params); // Regular Digishield v3
    else if (nHeight < params.nLwmaForkHeight)
        return LwmaGetNextWorkRequired(pindexLast, pblock, params, true); // Legacy Zawy's LWMA
    else
        return LwmaGetNextWorkRequired(pindexLast, pblock, params, false); // Zawy's LWMA
}

unsigned int DigishieldGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    LogPrint(BCLog::POW, "pindexLast->nHeight=%d, params.nEquihashForkHeight=%d params.nDigishieldAveragingWindow=%d\n",
             pindexLast->nHeight, params.nEquihashForkHeight, params.nDigishieldAveragingWindow);

    if (params.fPowAllowMinDifficultyBlocks)
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 6 * 2.5 minutes
        // then allow mining of a min-difficulty block.
        if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nDigishieldTargetSpacing * 6)
            return nProofOfWorkLimit;
    }

    // Reset the difficulty after the algo fork for testnet and regtest
    if (Params().NetworkIDString() != CBaseChainParams::MAIN) {
        if (((pindexLast->nHeight + 1) >= params.nEquihashForkHeight) && (pindexLast->nHeight < params.nEquihashForkHeight + params.nDigishieldAveragingWindow)) {
            LogPrint(BCLog::POW, "Reset the difficulty for the algorithm change: %d\n", nProofOfWorkLimit);
            return nProofOfWorkLimit;
        }
    } else {
        // Reset the difficulty after the algo fork
        if (((pindexLast->nHeight + 1) >= 95005) && (pindexLast->nHeight < params.nEquihashForkHeight + params.nDigishieldAveragingWindow)) {
            LogPrint(BCLog::POW, "Reset the difficulty for the algorithm change: %d\n", nProofOfWorkLimit);
            return nProofOfWorkLimit;
        }
    }

    // Find the first block in the averaging interval
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pindexFirst && i < params.nDigishieldAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }

    // Check we have enough blocks
    if (pindexFirst == NULL)
        return nProofOfWorkLimit;

    arith_uint256 bnAvg {bnTot / params.nDigishieldAveragingWindow};

    return DigishieldCalculateNextWorkRequired(pindexLast, bnAvg, pindexFirst->GetMedianTimePast(), params);
}

unsigned int DigishieldCalculateNextWorkRequired(const CBlockIndex* pindexLast, arith_uint256 bnAvg, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    // Use medians to prevent time-warp attacks
    int64_t nActualTimespan = pindexLast->GetMedianTimePast() - nFirstBlockTime;
    LogPrint(BCLog::POW, "  nActualTimespan = %d  before dampening\n", nActualTimespan);
    nActualTimespan = params.DigishieldAveragingWindowTimespan() + (nActualTimespan - params.DigishieldAveragingWindowTimespan())/4;
    LogPrint(BCLog::POW, "  nActualTimespan = %d  before bounds\n", nActualTimespan);

    // Limit adjustment step
    if (nActualTimespan < params.DigishieldMinActualTimespan())
        nActualTimespan = params.DigishieldMinActualTimespan();
    if (nActualTimespan > params.DigishieldMaxActualTimespan())
        nActualTimespan = params.DigishieldMaxActualTimespan();

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew {bnAvg};
    bnNew /= params.DigishieldAveragingWindowTimespan();
    bnNew *= nActualTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    // debug print
    LogPrint(BCLog::POW, "GetNextWorkRequired RETARGET\n");
    LogPrint(BCLog::POW, "params.DigishieldAveragingWindowTimespan() = %d    nActualTimespan = %d\n", params.DigishieldAveragingWindowTimespan(), nActualTimespan);
    LogPrint(BCLog::POW, "Current average: %08x  %s\n", bnAvg.GetCompact(), bnAvg.ToString());
    LogPrint(BCLog::POW, "After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

unsigned int LwmaGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, bool fLegacy)
{
    // Special difficulty rule for testnet:
    // If the new block's timestamp is more than 2 * 10 minutes
    // then allow mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) {
        return UintToArith256(params.powLimit).GetCompact();
    }
    return LwmaCalculateNextWorkRequired(pindexLast, params, fLegacy);
}

unsigned int LwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params, bool fLegacy)
{
    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    arith_uint256 nextTarget;
    arith_uint256 avgTarget;

    if (fLegacy) {
        // Define a k that will be used to get a proper average after weighting the solvetimes.
        const int64_t T = params.nLegacyPowTargetSpacing;
        const int64_t N = params.nLegacyLwmaAveragingWindow;
        const int64_t k = N * (N + 1) * T / 2;

        const int64_t height = pindexLast->nHeight;

        // New coins just "give away" first N blocks. It's better to guess
        // this value instead of using powLimit, but err on high side to not get stuck.
        if (height < N) { return powLimit.GetCompact(); }

        int64_t thisTimestamp, previousTimestamp;
        int64_t sumWeightedSolvetimes = 0, j = 0;

        const CBlockIndex* blockPreviousTimestamp = pindexLast->GetAncestor(height - N);
        previousTimestamp = blockPreviousTimestamp->GetBlockTime();

        // Loop through N most recent blocks.
        for (int64_t i = height - N + 1; i <= height; i++) {
            const CBlockIndex* block = pindexLast->GetAncestor(i);

            // Prevent solvetimes from being negative in a safe way. It must be done like this.
            // Do not attempt anything like  if (solvetime < 1) {solvetime=1;}
            // The +1 ensures new coins do not calculate nextTarget = 0.
            thisTimestamp = (block->GetBlockTime() > previousTimestamp) ? block->GetBlockTime() : previousTimestamp + 1;

            // 6*T limit prevents large drops in diff from long solvetimes which would cause oscillations.
            int64_t solvetime = std::min(6 * T, thisTimestamp - previousTimestamp);

            // The following is part of "preventing negative solvetimes".
            previousTimestamp = thisTimestamp;

            // Give linearly higher weight to more recent solvetimes.
            j++;
            sumWeightedSolvetimes += solvetime * j;

            arith_uint256 target;
            target.SetCompact(block->nBits);
            avgTarget += target / N / k; // Dividing by k here prevents an overflow below.
        }

        // Desired equation in next line was nextTarget = avgTarget * sumWeightSolvetimes / k
        // but 1/k was moved to line above to prevent overflow in new coins
        nextTarget = avgTarget * sumWeightedSolvetimes;
    } else {
        const int height = pindexLast->nHeight + 1;
        const int64_t T = params.nPowTargetSpacing;
        const int N = params.nLwmaAveragingWindow;
        const int k = params.nLwmaAdjustedWeight;
        const int dnorm = params.nLwmaMinDenominator;
        const bool limit_st = params.fLwmaSolvetimeLimitation;
        assert(height > N);

        int t = 0, j = 0;

        // Loop through N most recent blocks.
        for (int i = height - N; i < height; i++) {
            const CBlockIndex* block = pindexLast->GetAncestor(i);
            const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
            int64_t solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();

            if (limit_st && solvetime > 6 * T) {
                solvetime = 6 * T;
            }

            j++;
            t += solvetime * j;  // Weighted solvetime sum.

            // Target sum divided by a factor, (k N^2).
            // The factor is a part of the final equation. However we divide avgTarget here to avoid
            // potential overflow.
            arith_uint256 target;
            target.SetCompact(block->nBits);
            avgTarget += target / (k * N * N);
        }

        // Keep t reasonable in case strange solvetimes occurred.
        if (t < N * k / dnorm) {
            t = N * k / dnorm;
        }

        nextTarget = avgTarget * t;
    }

    if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    return nextTarget.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

bool CheckEquihashSolution(const CBlockHeader *pblock)
{
    // Derive n, k from the solution size as the block header does not specify parameters used.
    // In the future, we could pass in the block height and call EquihashN() and EquihashK()
    // to perform a contextual check against the parameters in use at a given block height.
    unsigned int n, k;
    size_t nSolSize = pblock->nSolution.size();

    // Equihash solution size = (pow(2, k) * ((n/(k+1))+1)) / 8
    if (nSolSize == 1344) { // mainnet and testnet genesis
        n = 200;
        k = 9;
    } else if (nSolSize == 36) { // regtest genesis
        n = 48;
        k = 5;
    } else if (nSolSize == 400) {
        n = 192;
        k = 7;
    } else if (nSolSize == 100) {
        n = 144;
        k = 5;
    } else if (nSolSize == 68) {
        n = 96;
        k = 5;
    } else {
        return error("CheckEquihashSolution: Unsupported solution size of %d", nSolSize);
    }

    LogPrint(BCLog::POW, "CheckEquihashSolution: selected n, k : %d, %d \n", n, k);

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);

    return isValid;
}
