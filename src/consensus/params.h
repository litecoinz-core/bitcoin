// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>
#include <map>
#include <string>

#include <boost/optional.hpp>

namespace Consensus {

/**
 * Index into Params.vUpgrades and NetworkUpgradeInfo
 *
 * Being array indices, these MUST be numbered consecutively.
 *
 * The order of these indices MUST match the order of the upgrades on-chain, as
 * several functions depend on the enum being sorted.
 */
enum UpgradeIndex : uint32_t {
    // Sprout must be first
    BASE_SPROUT,
    UPGRADE_TESTDUMMY,
    UPGRADE_OVERWINTER,
    UPGRADE_SAPLING,
    UPGRADE_ALPHERATZ,
    UPGRADE_PEGASI,
    // NOTE: Also add new upgrades to NetworkUpgradeInfo in upgrades.cpp
    MAX_NETWORK_UPGRADES
};

struct NetworkUpgrade {
    /**
     * The first protocol version which will understand the new consensus rules
     */
    int nProtocolVersion;

    /**
     * Height of the first block for which the new consensus rules will be active
     */
    int nActivationHeight;

    /**
     * Special value for nActivationHeight indicating that the upgrade is always active.
     * This is useful for testing, as it means tests don't need to deal with the activation
     * process (namely, faking a chain of somewhat-arbitrary length).
     *
     * New blockchains that want to enable upgrade rules from the beginning can also use
     * this value. However, additional care must be taken to ensure the genesis block
     * satisfies the enabled rules.
     */
    static constexpr int ALWAYS_ACTIVE = 0;

    /**
     * Special value for nActivationHeight indicating that the upgrade will never activate.
     * This is useful when adding upgrade code that has a testnet activation height, but
     * should remain disabled on mainnet.
     */
    static constexpr int NO_ACTIVATION_HEIGHT = -1;

    /**
     * The hash of the block at height nActivationHeight, if known. This is set manually
     * after a network upgrade activates.
     *
     * We use this in IsInitialBlockDownload to detect whether we are potentially being
     * fed a fake alternate chain. We use NU activation blocks for this purpose instead of
     * the checkpoint blocks, because network upgrades (should) have significantly more
     * scrutiny than regular releases. nMinimumChainWork MUST be set to at least the chain
     * work of this block, otherwise this detection will have false positives.
     */
    boost::optional<uint256> hashActivationBlock;
};

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    /**
     * Returns true if the given network upgrade is active as of the given block
     * height. Caller must check that the height is >= 0 (and handle unknown
     * heights).
     */
    bool NetworkUpgradeActive(int nHeight, Consensus::UpgradeIndex idx) const;

    uint256 hashGenesisBlock;

    bool fCoinbaseMustBeShielded;

    int nSubsidyHalvingInterval;
    /* BIP16 rule */
    bool BIP16Enabled;
    /* BIP34 rule */
    bool BIP34Enabled;
    /* BIP65 rule */
    bool BIP65Enabled;
    /* BIP66 rule */
    bool BIP66Enabled;
    /* ZIP209 rule */
    int ZIP209Enabled;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];

    /** Block height at which Zawy's LWMA difficulty algorithm becomes active */
    int nZawyLWMAHeight;

    /** Block height where Equihash<144,5> becomes active */
    int nEquihashForkHeight;
    /** Proof of work parameters */
    unsigned int nEquihashN1 = 0;
    unsigned int nEquihashK1 = 0;
    unsigned int nEquihashN2 = 0;
    unsigned int nEquihashK2 = 0;
    unsigned int EquihashN(int height = 0) const
    {
        if(height < nEquihashForkHeight) {
            return nEquihashN1;
        } else {
            return nEquihashN2;
        }
    }
    unsigned int EquihashK(int height = 0) const
    {
        if(height < nEquihashForkHeight) {
            return nEquihashK1;
        } else {
            return nEquihashK2;
        }
    }
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;

    // Params for Digishield difficulty adjustment algorithm.
    int64_t nDigishieldTargetSpacing;
    int64_t nDigishieldAveragingWindow;
    int64_t nDigishieldMaxAdjustDown;
    int64_t nDigishieldMaxAdjustUp;
    int64_t DigishieldAveragingWindowTimespan() const { return nDigishieldAveragingWindow * nDigishieldTargetSpacing; }
    int64_t DigishieldMinActualTimespan() const { return (DigishieldAveragingWindowTimespan() * (100 - nDigishieldMaxAdjustUp  )) / 100; }
    int64_t DigishieldMaxActualTimespan() const { return (DigishieldAveragingWindowTimespan() * (100 + nDigishieldMaxAdjustDown)) / 100; }

    // Params for Zawy's LWMA difficulty adjustment algorithm.
    int64_t nZawyLwmaAveragingWindow;
    int64_t nZawyLwmaAdjustedWeight;  // k = (N+1)/2 * 0.998 * T
    int64_t nZawyLwmaMinDenominator;
    bool bZawyLwmaSolvetimeLimitation;

    int64_t nPowTargetSpacing;
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    NetworkUpgrade vUpgrades[MAX_NETWORK_UPGRADES];

    int nApproxReleaseHeight;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
