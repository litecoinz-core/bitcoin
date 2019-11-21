// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
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
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    LogPrint(BCLog::POW, "pindexLast->nHeight=%d, params.nEquihashForkHeight=%d params.nPowAveragingWindow=%d\n",
             pindexLast->nHeight, params.nEquihashForkHeight, params.nPowAveragingWindow);

    if (params.fPowAllowMinDifficultyBlocks)
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* 10 minutes
        // then allow mining of a min-difficulty block.
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
            return nProofOfWorkLimit;
    }
    else
    {
        // Reset the difficulty after the algo fork for testnet and regtest
        if (Params().NetworkIDString() != CBaseChainParams::MAIN) {
            if (((pindexLast->nHeight + 1) >= params.nEquihashForkHeight) && (pindexLast->nHeight < params.nEquihashForkHeight + params.nPowAveragingWindow)) {
                LogPrint(BCLog::POW, "Reset the difficulty for the algorithm change: %d\n", nProofOfWorkLimit);
                return nProofOfWorkLimit;
            }
        } else {
            // Reset the difficulty after the algo fork
            if (((pindexLast->nHeight + 1) >= 95005) && (pindexLast->nHeight < params.nEquihashForkHeight + params.nPowAveragingWindow)) {
                LogPrint(BCLog::POW, "Reset the difficulty for the algorithm change: %d\n", nProofOfWorkLimit);
                return nProofOfWorkLimit;
            }
        }
    }

    // Find the first block in the averaging interval
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pindexFirst && i < params.nPowAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }

    // Check we have enough blocks
    if (pindexFirst == NULL)
        return nProofOfWorkLimit;

    arith_uint256 bnAvg {bnTot / params.nPowAveragingWindow};

    return CalculateNextWorkRequired(pindexLast, bnAvg, pindexFirst->GetMedianTimePast(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, arith_uint256 bnAvg, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Use medians to prevent time-warp attacks
    int64_t nActualTimespan = pindexLast->GetMedianTimePast() - nFirstBlockTime;
    LogPrint(BCLog::POW, "  nActualTimespan = %d  before dampening\n", nActualTimespan);
    nActualTimespan = params.AveragingWindowTimespan() + (nActualTimespan - params.AveragingWindowTimespan())/4;
    LogPrint(BCLog::POW, "  nActualTimespan = %d  before bounds\n", nActualTimespan);

    // Limit adjustment step
    if (nActualTimespan < params.MinActualTimespan())
        nActualTimespan = params.MinActualTimespan();
    if (nActualTimespan > params.MaxActualTimespan())
        nActualTimespan = params.MaxActualTimespan();

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew {bnAvg};
    bnNew /= params.AveragingWindowTimespan();
    bnNew *= nActualTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    // debug print
    LogPrint(BCLog::POW, "GetNextWorkRequired RETARGET\n");
    LogPrint(BCLog::POW, "params.AveragingWindowTimespan() = %d    nActualTimespan = %d\n", params.AveragingWindowTimespan(), nActualTimespan);
    LogPrint(BCLog::POW, "Current average: %08x  %s\n", bnAvg.GetCompact(), bnAvg.ToString());
    LogPrint(BCLog::POW, "After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
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
