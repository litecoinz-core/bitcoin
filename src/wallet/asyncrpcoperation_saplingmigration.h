// Copyright (c) 2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <asyncrpcoperation.h>
#include <rpc/request.h>
#include <wallet/wallet.h>
#include <zcash/Address.hpp>
#include <zcash/zip32.h>

#include <univalue.h>

class AsyncRPCOperation_saplingmigration : public AsyncRPCOperation
{
public:
    AsyncRPCOperation_saplingmigration(size_t targetHeight, const JSONRPCRequest& request);
    virtual ~AsyncRPCOperation_saplingmigration();

    // We don't want to be copied or moved around
    AsyncRPCOperation_saplingmigration(AsyncRPCOperation_saplingmigration const&) = delete;            // Copy construct
    AsyncRPCOperation_saplingmigration(AsyncRPCOperation_saplingmigration&&) = delete;                 // Move construct
    AsyncRPCOperation_saplingmigration& operator=(AsyncRPCOperation_saplingmigration const&) = delete; // Copy assign
    AsyncRPCOperation_saplingmigration& operator=(AsyncRPCOperation_saplingmigration&&) = delete;      // Move assign

    static libzcash::SaplingPaymentAddress getMigrationDestAddress(const HDSeed& seed, CWallet* const pwallet);

    virtual void main();

    virtual void cancel();

    virtual UniValue getStatus() const;

private:
    size_t targetHeight_;
    JSONRPCRequest request_;

    bool main_impl();

    void setMigrationResult(int numTxCreated, const CAmount& amountMigrated, const std::vector<std::string>& migrationTxIds);

    CAmount chooseAmount(const CAmount& availableFunds);
};
