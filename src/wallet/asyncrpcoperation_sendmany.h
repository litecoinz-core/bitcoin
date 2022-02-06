// Copyright (c) 2016 The Zcash developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ASYNCRPCOPERATION_SENDMANY_H
#define ASYNCRPCOPERATION_SENDMANY_H

#include <amount.h>
#include <asyncrpcoperation.h>
#include <primitives/transaction.h>
#include <rpc/request.h>
#include <transaction_builder.h>
#include <wallet/wallet.h>
#include <zcash/Address.hpp>
#include <zcash/JoinSplit.hpp>

#include <array>
#include <tuple>
#include <unordered_map>

#include <univalue.h>

// Default transaction fee if caller does not specify one.
#define ASYNC_RPC_OPERATION_DEFAULT_MINERS_FEE   10000

class TxValues;

class SendManyRecipient {
public:
    std::string address;
    CAmount amount;
    std::string memo;

    SendManyRecipient(std::string address_, CAmount amount_, std::string memo_ = "") :
        address(address_), amount(amount_), memo(memo_) {}
};

class AsyncRPCOperation_sendmany : public AsyncRPCOperation {
public:
    AsyncRPCOperation_sendmany(
        CWallet* const pwallet,
        Optional<TransactionBuilder> builder,
        CMutableTransaction contextualTx,
        std::string fromAddress,
        std::vector<SendManyRecipient> tOutputs,
        std::vector<SendManyRecipient> zOutputs,
        int minDepth,
        CAmount fee = ASYNC_RPC_OPERATION_DEFAULT_MINERS_FEE,
        UniValue contextInfo = NullUniValue);
    virtual ~AsyncRPCOperation_sendmany();

    // We don't want to be copied or moved around
    AsyncRPCOperation_sendmany(AsyncRPCOperation_sendmany const&) = delete;             // Copy construct
    AsyncRPCOperation_sendmany(AsyncRPCOperation_sendmany&&) = delete;                  // Move construct
    AsyncRPCOperation_sendmany& operator=(AsyncRPCOperation_sendmany const&) = delete;  // Copy assign
    AsyncRPCOperation_sendmany& operator=(AsyncRPCOperation_sendmany &&) = delete;      // Move assign

    virtual void main();

    virtual UniValue getStatus() const;

    bool testmode = false;  // Set to true to disable sending txs and generating proofs

    bool paymentDisclosureMode = false; // Set to true to save esk for encrypted notes in payment disclosure database.

private:
    CWallet* pwallet_;
    CTransactionRef tx_;
    std::string fromaddress_;
    std::vector<SendManyRecipient> t_outputs_;
    std::vector<SendManyRecipient> z_outputs_;
    int mindepth_;
    CAmount fee_;
    UniValue contextinfo_;     // optional data to include in return value from getStatus()

    bool isfromtaddr_;
    bool isfromzaddr_;
    CTxDestination fromtaddr_;
    libzcash::PaymentAddress frompaymentaddress_;
    libzcash::SpendingKey spendingkey_;

    std::vector<COutput> t_inputs_;
    std::vector<SaplingNoteEntry> z_sapling_inputs_;

    TransactionBuilder builder_;

    bool find_unspent_notes();
    bool find_utxos(TxValues& txValues);
    // Load transparent inputs into the transaction or the transactionBuilder (in case of have it)
    bool load_inputs(TxValues& txValues);
    std::array<unsigned char, ZC_MEMO_SIZE> get_memo_from_hex_string(std::string s);
    bool main_impl();
};

#endif /* ASYNCRPCOPERATION_SENDMANY_H */
