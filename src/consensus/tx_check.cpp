// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <consensus/upgrades.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <zcashparams.h>

bool IsExpiredTx(const CTransaction &tx, int nBlockHeight)
{
    if (tx.nExpiryHeight == 0 || tx.IsCoinBase()) {
        return false;
    }
    return (uint32_t)nBlockHeight > tx.nExpiryHeight;
}

bool IsExpiringSoonTx(const CTransaction &tx, int nNextBlockHeight)
{
    return IsExpiredTx(tx, nNextBlockHeight + TX_EXPIRING_SOON_THRESHOLD);
}

/**
 * Check a transaction contextually against a set of consensus rules valid at a given block height.
 *
 * Notes:
 * 1. AcceptToMemoryPool calls CheckTransaction and this function.
 * 2. ProcessNewBlock calls AcceptBlock, which calls CheckBlock (which calls CheckTransaction)
 *    and ContextualCheckBlock (which calls this function).
 * 3. The isInitBlockDownload argument is only to assist with testing.
 */
bool ContextualCheckTransaction(const CTransaction& tx, CValidationState &state, const int nHeight)
{
    const CChainParams& chainparams = Params();

    bool overwinterActive = chainparams.GetConsensus().NetworkUpgradeActive(nHeight, Consensus::UPGRADE_OVERWINTER);
    bool saplingActive = chainparams.GetConsensus().NetworkUpgradeActive(nHeight, Consensus::UPGRADE_SAPLING);
    bool isSprout = !overwinterActive;

    // If Sprout rules apply, reject transactions which are intended for Overwinter and beyond
    if (isSprout && tx.fOverwintered)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "tx-overwinter-not-active");

    if (saplingActive) {
        // Reject transactions with valid version but missing overwintered flag
        if (tx.nVersion >= SAPLING_MIN_TX_VERSION && !tx.fOverwintered)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "tx-overwintered-flag-not-set");

        // Reject transactions with non-Sapling version group ID
        if (tx.fOverwintered && tx.nVersionGroupId != SAPLING_VERSION_GROUP_ID)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-sapling-tx-version-group-id");

        // Reject transactions with invalid version
        if (tx.fOverwintered && tx.nVersion < SAPLING_MIN_TX_VERSION)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-tx-sapling-version-too-low");

        // Reject transactions with invalid version
        if (tx.fOverwintered && tx.nVersion > SAPLING_MAX_TX_VERSION)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-tx-sapling-version-too-high");
    } else if (overwinterActive) {
        // Reject transactions with valid version but missing overwinter flag
        if (tx.nVersion >= OVERWINTER_MIN_TX_VERSION && !tx.fOverwintered)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "tx-overwinter-flag-not-set");

        // Reject transactions with non-Overwinter version group ID
        if (tx.fOverwintered && tx.nVersionGroupId != OVERWINTER_VERSION_GROUP_ID)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-overwinter-tx-version-group-id");

        // Reject transactions with invalid version
        if (tx.fOverwintered && tx.nVersion > OVERWINTER_MAX_TX_VERSION)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-tx-overwinter-version-too-high");
    }

    // Rules that apply to Overwinter or later:
    if (overwinterActive) {
        // Reject transactions intended for Sprout
        if (!tx.fOverwintered)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "tx-overwinter-active");

        // Check that all transactions are unexpired
        if (IsExpiredTx(tx, nHeight))
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "tx-overwinter-expired");
    }

    // Rules that apply before Sapling:
    if (!saplingActive) {
        // Size limits
        if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-oversize");
    }

    auto consensusBranchId = CurrentEpochBranchId(nHeight, chainparams.GetConsensus());
    auto prevConsensusBranchId = PrevEpochBranchId(consensusBranchId, chainparams.GetConsensus());
    uint256 dataToBeSigned;
    uint256 prevDataToBeSigned;

    if (!tx.vJoinSplit.empty() ||
        !tx.vShieldedSpend.empty() ||
        !tx.vShieldedOutput.empty())
    {
        SigVersion sigversion = SigVersion::BASE;
        if (tx.fOverwintered) {
            if (tx.nVersionGroupId == SAPLING_VERSION_GROUP_ID) {
                sigversion = SigVersion::SAPLING_V0;
            } else {
                sigversion = SigVersion::OVERWINTER;
            }
        }

        // Empty output script.
        CScript scriptCode;
        try {
            dataToBeSigned = SignatureHash(scriptCode, tx, NOT_AN_INPUT, SIGHASH_ALL, 0, sigversion, consensusBranchId);
            prevDataToBeSigned = SignatureHash(scriptCode, tx, NOT_AN_INPUT, SIGHASH_ALL, 0, sigversion, prevConsensusBranchId);
        } catch (std::logic_error& ex) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "error-computing-signature-hash");
        }
    }

    if (!tx.vJoinSplit.empty())
    {
        BOOST_STATIC_ASSERT(crypto_sign_PUBLICKEYBYTES == 32);

        // We rely on libsodium to check that the signature is canonical.
        // https://github.com/jedisct1/libsodium/commit/62911edb7ff2275cccd74bf1c8aefcc4d76924e0
        if (crypto_sign_verify_detached(&tx.joinSplitSig[0],
                                        dataToBeSigned.begin(), 32,
                                        tx.joinSplitPubKey.begin()
                                        ) != 0) {
            // Check whether the failure was caused by an outdated consensus
            // branch ID; if so, inform the node that they need to upgrade. We
            // only check the previous epoch's branch ID, on the assumption that
            // users creating transactions will notice their transactions
            // failing before a second network upgrade occurs.
            if (crypto_sign_verify_detached(&tx.joinSplitSig[0],
                                            prevDataToBeSigned.begin(), 32,
                                            tx.joinSplitPubKey.begin()
                                            ) == 0) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID,
                       strprintf("old-consensus-branch-id (Expected %s, found %s)", HexInt(consensusBranchId), HexInt(prevConsensusBranchId)));
            }
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-invalid-joinsplit-signature");
        }
    }

    if (!tx.vShieldedSpend.empty() ||
        !tx.vShieldedOutput.empty())
    {
        auto ctx = librustzcash_sapling_verification_ctx_init();

        for (const SpendDescription &spend : tx.vShieldedSpend) {
            if (!librustzcash_sapling_check_spend(
                ctx,
                spend.cv.begin(),
                spend.anchor.begin(),
                spend.nullifier.begin(),
                spend.rk.begin(),
                spend.zkproof.begin(),
                spend.spendAuthSig.begin(),
                dataToBeSigned.begin()
            ))
            {
                librustzcash_sapling_verification_ctx_free(ctx);
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-sapling-spend-description-invalid");
            }
        }

        for (const OutputDescription &output : tx.vShieldedOutput) {
            if (!librustzcash_sapling_check_output(
                ctx,
                output.cv.begin(),
                output.cm.begin(),
                output.ephemeralKey.begin(),
                output.zkproof.begin()
            ))
            {
                librustzcash_sapling_verification_ctx_free(ctx);
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-sapling-output-description-invalid");
            }
        }

        if (!librustzcash_sapling_final_check(
            ctx,
            tx.valueBalance,
            tx.bindingSig.begin(),
            dataToBeSigned.begin()
        ))
        {
            librustzcash_sapling_verification_ctx_free(ctx);
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-sapling-binding-signature-invalid");
        }

        librustzcash_sapling_verification_ctx_free(ctx);
    }
    return true;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, libzcash::ProofVerifier& verifier, bool fCheckDuplicateInputs)
{
    if (!CheckTransactionWithoutProofVerification(tx, state, fCheckDuplicateInputs)) {
        return false;
    } else {
        // Ensure that zk-SNARKs verify
        for (const JSDescription &joinsplit : tx.vJoinSplit) {
            if (!joinsplit.Verify(*pzcashParams, verifier, tx.joinSplitPubKey))
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-joinsplit-verification-failed");
        }
        return true;
    }
}

bool CheckTransactionWithoutProofVerification(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
/**
     * Previously:
     * 1. The consensus rule below was:
     *        if (tx.nVersion < SPROUT_MIN_TX_VERSION) { ... }
     *    which checked if tx.nVersion fell within the range:
     *        INT32_MIN <= tx.nVersion < SPROUT_MIN_TX_VERSION
     * 2. The parser allowed tx.nVersion to be negative
     *
     * Now:
     * 1. The consensus rule checks to see if tx.Version falls within the range:
     *        0 <= tx.nVersion < SPROUT_MIN_TX_VERSION
     * 2. The previous consensus rule checked for negative values within the range:
     *        INT32_MIN <= tx.nVersion < 0
     *    This is unnecessary for Overwinter transactions since the parser now
     *    interprets the sign bit as fOverwintered, so tx.nVersion is always >=0,
     *    and when Overwinter is not active ContextualCheckTransaction rejects
     *    transactions with fOverwintered set.  When fOverwintered is set,
     *    this function and ContextualCheckTransaction will together check to
     *    ensure tx.nVersion avoids the following ranges:
     *        0 <= tx.nVersion < OVERWINTER_MIN_TX_VERSION
     *        OVERWINTER_MAX_TX_VERSION < tx.nVersion <= INT32_MAX
     */
    if (!tx.fOverwintered && tx.nVersion < SPROUT_MIN_TX_VERSION) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-version-too-low");
    }
    else if (tx.fOverwintered) {
        if (tx.nVersion < OVERWINTER_MIN_TX_VERSION)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-tx-overwinter-version-too-low");
        if (tx.nVersionGroupId != OVERWINTER_VERSION_GROUP_ID && tx.nVersionGroupId != SAPLING_VERSION_GROUP_ID)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-tx-version-group-id");
        if (tx.nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-tx-expiry-height-too-high");
    }

    // Transactions containing empty `vin` must have either non-empty
    // `vJoinSplit` or non-empty `vShieldedSpend`.
    if (tx.vin.empty() && tx.vJoinSplit.empty() && tx.vShieldedSpend.empty())
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vin-empty");
    // Transactions containing empty `vout` must have either non-empty
    // `vJoinSplit` or non-empty `vShieldedOutput`.
    if (tx.vout.empty() && tx.vJoinSplit.empty() && tx.vShieldedOutput.empty())
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for non-zero valueBalance when there are no Sapling inputs or outputs
    if (tx.vShieldedSpend.empty() && tx.vShieldedOutput.empty() && tx.valueBalance != 0)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-valuebalance-nonzero");

    // Check for overflow valueBalance
    if (tx.valueBalance > MAX_MONEY || tx.valueBalance < -MAX_MONEY)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-valuebalance-toolarge");

    if (tx.valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -tx.valueBalance;

        if (!MoneyRange(nValueOut))
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Ensure that joinsplit values are well-formed
    for (const JSDescription& joinsplit : tx.vJoinSplit)
    {
        if (joinsplit.vpub_old < 0)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vpub_old-negative");

        if (joinsplit.vpub_new < 0)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vpub_new-negative");

        if (joinsplit.vpub_old > MAX_MONEY)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vpub_old-toolarge");

        if (joinsplit.vpub_new > MAX_MONEY)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vpub_new-toolarge");

        if (joinsplit.vpub_new != 0 && joinsplit.vpub_old != 0)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vpubs-both-nonzero");

        nValueOut += joinsplit.vpub_old;
        if (!MoneyRange(nValueOut))
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Ensure input values do not exceed MAX_MONEY
    // We have not resolved the txin values at this stage,
    // but we do know what the joinsplits claim to add
    // to the value pool.
    {
        CAmount nValueIn = 0;
        for (std::vector<JSDescription>::const_iterator it(tx.vJoinSplit.begin()); it != tx.vJoinSplit.end(); ++it)
        {
            nValueIn += it->vpub_new;

            if (!MoneyRange(it->vpub_new) || !MoneyRange(nValueIn))
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txintotal-toolarge");
        }

        // Also check for Sapling
        if (tx.valueBalance >= 0) {
            // NB: positive valueBalance "adds" money to the transparent value pool, just as inputs do
            nValueIn += tx.valueBalance;

            if (!MoneyRange(nValueIn))
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txintotal-toolarge");
        }
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin)
        {
            if (!vInOutPoints.insert(txin.prevout).second)
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }

        // Check for duplicate sprout nullifiers in this transaction
        std::set<uint256> vJoinSplitNullifiers;
        for (const JSDescription& joinsplit : tx.vJoinSplit)
        {
            for (const uint256& nf : joinsplit.nullifiers)
            {
                if (!vJoinSplitNullifiers.insert(nf).second)
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-joinsplits-nullifiers-duplicate");
            }
        }

        // Check for duplicate sapling nullifiers in this transaction
        {
            std::set<uint256> vSaplingNullifiers;
            for (const SpendDescription& spend_desc : tx.vShieldedSpend)
            {
                if (!vSaplingNullifiers.insert(spend_desc.nullifier).second)
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-spend-description-nullifiers-duplicate");
            }
        }
    }

    if (tx.IsCoinBase())
    {
        // There should be no joinsplits in a coinbase transaction
        if (tx.vJoinSplit.size() > 0)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-has-joinsplits");
        // A coinbase transaction cannot have spend descriptions or output descriptions
        if (tx.vShieldedSpend.size() > 0)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-has-spend-description");
        if (tx.vShieldedOutput.size() > 0)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-has-output-description");

        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}
