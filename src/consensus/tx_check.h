// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_TX_CHECK_H
#define BITCOIN_CONSENSUS_TX_CHECK_H

#include <chainparams.h>
#include <zcash/Proof.hpp>

#include <librustzcash.h>

/**
 * Context-independent transaction checking code that can be called outside the
 * bitcoin server and doesn't depend on chain or mempool state. Transaction
 * verification code that does call server functions or depend on server state
 * belongs in tx_verify.h/cpp instead.
 */

class CChainParams;
class CTransaction;
class CValidationState;

/** Check a transaction contextually against a set of consensus rules */
bool ContextualCheckTransaction(const CTransaction& tx, CValidationState &state, int nHeight);

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction& tx, CValidationState& state, libzcash::ProofVerifier& verifier, bool fCheckDuplicateInputs=true);
bool CheckTransactionWithoutProofVerification(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs);

#endif // BITCOIN_CONSENSUS_TX_CHECK_H
