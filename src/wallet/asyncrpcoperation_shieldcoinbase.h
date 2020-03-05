// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ASYNCRPCOPERATION_SHIELDCOINBASE_H
#define ASYNCRPCOPERATION_SHIELDCOINBASE_H

#include <amount.h>
#include <asyncrpcoperation.h>
#include <primitives/transaction.h>
#include <rpc/request.h>
#include <transaction_builder.h>
#include <wallet/paymentdisclosure.h>
#include <wallet/wallet.h>
#include <zcash/Address.hpp>
#include <zcash/JoinSplit.hpp>

#include <tuple>
#include <unordered_map>

#include <univalue.h>

// Default transaction fee if caller does not specify one.
#define SHIELD_COINBASE_DEFAULT_MINERS_FEE   10000

class ShieldCoinbaseUTXO {
public:
    uint256 txid;
    int vout;
    CScript script;
    CAmount amount;

    ShieldCoinbaseUTXO(uint256 txid_, int vout_, CScript script_, CAmount amount_)
    {
        txid = txid_;
        vout = vout_;
        script = script_;
        amount = amount_;
    }
};

// Package of info which is passed to perform_joinsplit methods.
struct ShieldCoinbaseJSInfo
{
    std::vector<libzcash::JSInput> vjsin;
    std::vector<libzcash::JSOutput> vjsout;
    CAmount vpub_old = 0;
    CAmount vpub_new = 0;
};

class AsyncRPCOperation_shieldcoinbase : public AsyncRPCOperation {
public:
    AsyncRPCOperation_shieldcoinbase(
        const JSONRPCRequest& request,
        boost::optional<TransactionBuilder> builder,
        CMutableTransaction contextualTx,
        std::vector<ShieldCoinbaseUTXO> tInputs,
        std::string zOutput,
        CAmount fee = SHIELD_COINBASE_DEFAULT_MINERS_FEE,
        UniValue contextInfo = NullUniValue);
    virtual ~AsyncRPCOperation_shieldcoinbase();

    // We don't want to be copied or moved around
    AsyncRPCOperation_shieldcoinbase(AsyncRPCOperation_shieldcoinbase const&) = delete;             // Copy construct
    AsyncRPCOperation_shieldcoinbase(AsyncRPCOperation_shieldcoinbase&&) = delete;                  // Move construct
    AsyncRPCOperation_shieldcoinbase& operator=(AsyncRPCOperation_shieldcoinbase const&) = delete;  // Copy assign
    AsyncRPCOperation_shieldcoinbase& operator=(AsyncRPCOperation_shieldcoinbase &&) = delete;      // Move assign

    virtual void main();

    virtual UniValue getStatus() const;

    bool testmode = false;  // Set to true to disable sending txs and generating proofs

    bool paymentDisclosureMode = false; // Set to true to save esk for encrypted notes in payment disclosure database.

private:
    JSONRPCRequest request_;
    CTransactionRef tx_;
    std::vector<ShieldCoinbaseUTXO> t_inputs_;
    std::string z_output_;
    CAmount fee_;
    UniValue contextinfo_;     // optional data to include in return value from getStatus()

    bool isUsingBuilder_; // Indicates that no Sprout addresses are involved
    uint32_t consensusBranchId_;

    uint256 joinSplitPubKey_;
    unsigned char joinSplitPrivKey_[crypto_sign_SECRETKEYBYTES];

    TransactionBuilder builder_;

    bool main_impl();

    // JoinSplit without any input notes to spend
    UniValue perform_joinsplit(ShieldCoinbaseJSInfo &);

    // JoinSplit with input notes to spend (SproutOutPoints))
    UniValue perform_joinsplit(ShieldCoinbaseJSInfo &, std::vector<SproutOutPoint> & );

    // JoinSplit where you have the witnesses and anchor
    UniValue perform_joinsplit(
        ShieldCoinbaseJSInfo & info,
        std::vector<boost::optional < SproutWitness>> witnesses,
        uint256 anchor);

    // payment disclosure!
    std::vector<PaymentDisclosureKeyInfo> paymentDisclosureData_;
};

#endif /* ASYNCRPCOPERATION_SHIELDCOINBASE_H */
