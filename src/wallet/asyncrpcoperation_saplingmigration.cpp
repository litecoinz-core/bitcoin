// Copyright (c) 2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/asyncrpcoperation_saplingmigration.h>

#include <assert.h>
#include <init.h>
#include <key_io.h>
#include <random.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <sync.h>
#include <tinyformat.h>
#include <transaction_builder.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <validation.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <zcashparams.h>

#include <boost/variant/static_visitor.hpp>

static constexpr CAmount FEE{10000};
const size_t MIGRATION_EXPIRY_DELTA = 450;

AsyncRPCOperation_saplingmigration::AsyncRPCOperation_saplingmigration(size_t targetHeight, const JSONRPCRequest& request) :
    targetHeight_(targetHeight), request_(request) {}

AsyncRPCOperation_saplingmigration::~AsyncRPCOperation_saplingmigration() {}

void AsyncRPCOperation_saplingmigration::main() {
    if (isCancelled())
        return;

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;

    try {
        success = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
    } catch (const std::runtime_error& e) {
        set_error_code(-1);
        set_error_message("runtime error: " + std::string(e.what()));
    } catch (const std::logic_error& e) {
        set_error_code(-1);
        set_error_message("logic error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        set_error_code(-1);
        set_error_message("general exception: " + std::string(e.what()));
    } catch (...) {
        set_error_code(-2);
        set_error_message("unknown error");
    }

    stop_execution_clock();

    if (success) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: Sprout->Sapling transactions created. (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", success)\n");
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }

    LogPrintf("%s", s);
}

bool AsyncRPCOperation_saplingmigration::main_impl() {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();
    auto locked_chain = pwallet->chain().lock();

    LogPrint(BCLog::ZRPCUNSAFE, "%s: Beginning AsyncRPCOperation_saplingmigration.\n", getId());
    auto consensusParams = Params().GetConsensus();
    auto nextActivationHeight = NextActivationHeight(targetHeight_, consensusParams);
    if (nextActivationHeight && targetHeight_ + MIGRATION_EXPIRY_DELTA >= nextActivationHeight.get()) {
        LogPrint(BCLog::ZRPCUNSAFE, "%s: Migration txs would be created before a NU activation but may expire after. Skipping this round.\n", getId());
        setMigrationResult(0, 0, std::vector<std::string>());
        return true;
    }

    std::vector<SproutNoteEntry> sproutEntries;
    std::vector<SaplingNoteEntry> saplingEntries;
    {
        LOCK2(cs_main, pwallet->cs_wallet);
        // We set minDepth to 11 to avoid unconfirmed notes and in anticipation of specifying
        // an anchor at height N-10 for each Sprout JoinSplit description
        // Consider, should notes be sorted?
        pwallet->GetFilteredNotes(*locked_chain, sproutEntries, saplingEntries, "", 11);
    }
    CAmount availableFunds = 0;
    for (const SproutNoteEntry& sproutEntry : sproutEntries) {
        availableFunds += sproutEntry.note.value();
    }
    // If the remaining amount to be migrated is less than 0.01 ZEC, end the migration.
    if (availableFunds < CENT) {
        LogPrint(BCLog::ZRPCUNSAFE, "%s: Available Sprout balance (%s) less than required minimum (%s). Stopping.\n",
            getId(), FormatMoney(availableFunds), FormatMoney(CENT));
        setMigrationResult(0, 0, std::vector<std::string>());
        return true;
    }

    HDSeed seed = pwallet->GetZecHDSeedForRPC(pwallet);
    libzcash::SaplingPaymentAddress migrationDestAddress = getMigrationDestAddress(seed, pwallet);

    // Up to the limit of 5, as many transactions are sent as are needed to migrate the remaining funds
    int numTxCreated = 0;
    CAmount amountMigrated = 0;
    std::vector<std::string> migrationTxIds;
    int noteIndex = 0;
    CCoinsViewCache coinsView(&::ChainstateActive().CoinsTip());
    do {
        CAmount amountToSend = chooseAmount(availableFunds);
        auto builder = TransactionBuilder(consensusParams, targetHeight_, pwallet, pzcashParams, &coinsView, &cs_main);
        builder.SetExpiryHeight(targetHeight_ + MIGRATION_EXPIRY_DELTA);
        LogPrint(BCLog::ZRPCUNSAFE, "%s: Beginning creating transaction with Sapling output amount=%s\n", getId(), FormatMoney(amountToSend - FEE));
        std::vector<SproutNoteEntry> fromNotes;
        CAmount fromNoteAmount = 0;
        while (fromNoteAmount < amountToSend) {
            auto sproutEntry = sproutEntries[noteIndex++];
            fromNotes.push_back(sproutEntry);
            fromNoteAmount += sproutEntry.note.value();
        }
        availableFunds -= fromNoteAmount;
        for (const SproutNoteEntry& sproutEntry : fromNotes) {
            std::string data(sproutEntry.memo.begin(), sproutEntry.memo.end());
            LogPrint(BCLog::ZRPCUNSAFE, "%s: Adding Sprout note input (txid=%s, vJoinSplit=%d, jsoutindex=%d, amount=%s, memo=%s)\n",
                getId(),
                sproutEntry.jsop.hash.ToString().substr(0, 10),
                sproutEntry.jsop.js,
                int(sproutEntry.jsop.n),  // uint8_t
                FormatMoney(sproutEntry.note.value()),
                HexStr(data).substr(0, 10)
                );
            libzcash::SproutSpendingKey sproutSk;
            pwallet->GetSproutSpendingKey(sproutEntry.address, sproutSk);
            std::vector<JSOutPoint> vOutPoints = {sproutEntry.jsop};
            // Each migration transaction SHOULD specify an anchor at height N-10
            // for each Sprout JoinSplit description
            // TODO: the above functionality (in comment) is not implemented in zcashd
            uint256 inputAnchor;
            std::vector<boost::optional<SproutWitness>> vInputWitnesses;
            pwallet->GetSproutNoteWitnesses(vOutPoints, vInputWitnesses, inputAnchor);
            builder.AddSproutInput(sproutSk, sproutEntry.note, vInputWitnesses[0].get());
        }
        // The amount chosen *includes* the 0.0001 ZEC fee for this transaction, i.e.
        // the value of the Sapling output will be 0.0001 ZEC less.
        builder.SetFee(FEE);
        builder.AddSaplingOutput(ovkForShieldingFromTaddr(seed), migrationDestAddress, amountToSend - FEE);
        CTransactionRef tx = builder.Build().GetTxOrThrow();
        if (isCancelled()) {
            LogPrint(BCLog::ZRPCUNSAFE, "%s: Canceled. Stopping.\n", getId());
            break;
        }
        pwallet->AddPendingSaplingMigrationTx(tx);
        LogPrint(BCLog::ZRPCUNSAFE, "%s: Added pending migration transaction with txid=%s\n", getId(), tx->GetHash().ToString());
        ++numTxCreated;
        amountMigrated += amountToSend - FEE;
        migrationTxIds.push_back(tx->GetHash().ToString());
    } while (numTxCreated < 5 && availableFunds > CENT);

    LogPrint(BCLog::ZRPCUNSAFE, "%s: Created %d transactions with total Sapling output amount=%s\n", getId(), numTxCreated, FormatMoney(amountMigrated));
    setMigrationResult(numTxCreated, amountMigrated, migrationTxIds);
    return true;
}

void AsyncRPCOperation_saplingmigration::setMigrationResult(int numTxCreated, const CAmount& amountMigrated, const std::vector<std::string>& migrationTxIds) {
    UniValue res(UniValue::VOBJ);
    res.pushKV("num_tx_created", numTxCreated);
    res.pushKV("amount_migrated", FormatMoney(amountMigrated));
    UniValue txIds(UniValue::VARR);
    for (const std::string& txId : migrationTxIds) {
        txIds.push_back(txId);
    }
    res.pushKV("migration_txids", txIds);
    set_result(res);
}

CAmount AsyncRPCOperation_saplingmigration::chooseAmount(const CAmount& availableFunds) {
    CAmount amount = 0;
    do {
        // 1. Choose an integer exponent uniformly in the range 6 to 8 inclusive.
        int exponent = GetRand(3) + 6;
        // 2. Choose an integer mantissa uniformly in the range 1 to 99 inclusive.
        uint64_t mantissa = GetRand(99) + 1;
        // 3. Calculate amount := (mantissa * 10^exponent) zatoshi.
        int pow = std::pow(10, exponent);
        amount = mantissa * pow;
        // 4. If amount is greater than the amount remaining to send, repeat from step 1.
    } while (amount > availableFunds);
    return amount;
}

// Unless otherwise specified, the migration destination address is the address for Sapling account 0
libzcash::SaplingPaymentAddress AsyncRPCOperation_saplingmigration::getMigrationDestAddress(const HDSeed& seed, CWallet* const pwallet) {
    if (gArgs.IsArgSet("-migrationdestaddress")) {
        std::string migrationDestAddress = gArgs.GetArg("-migrationdestaddress", "");
        auto address = DecodePaymentAddress(migrationDestAddress);
        auto saplingAddress = boost::get<libzcash::SaplingPaymentAddress>(&address);
        assert(saplingAddress != nullptr); // This is checked in init.cpp
        return *saplingAddress;
    }
    // Derive the address for Sapling account 0
    auto m = libzcash::SaplingExtendedSpendingKey::Master(seed);
    uint32_t bip44CoinType = Params().BIP44CoinType();

    // We use a fixed keypath scheme of m/32'/coin_type'/account'
    // Derive m/32'
    auto m_32h = m.Derive(32 | ZIP32_HARDENED_KEY_LIMIT);
    // Derive m/32'/coin_type'
    auto m_32h_cth = m_32h.Derive(bip44CoinType | ZIP32_HARDENED_KEY_LIMIT);

    // Derive m/32'/coin_type'/0'
    libzcash::SaplingExtendedSpendingKey xsk = m_32h_cth.Derive(0 | ZIP32_HARDENED_KEY_LIMIT);

    libzcash::SaplingPaymentAddress toAddress = xsk.DefaultAddress();

    // Refactor: this is similar logic as in the visitor HaveSpendingKeyForPaymentAddress and is used elsewhere
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingFullViewingKey fvk;
    if (!(pwallet->GetSaplingIncomingViewingKey(toAddress, ivk) &&
        pwallet->GetSaplingFullViewingKey(ivk, fvk) &&
        pwallet->HaveSaplingSpendingKey(fvk))) {
        // Sapling account 0 must be the first address returned by GenerateNewSaplingZKey
        assert(pwallet->GenerateNewSaplingZKey() == toAddress);
    }

    return toAddress;
}

void AsyncRPCOperation_saplingmigration::cancel() {
    set_state(OperationStatus::CANCELLED);
}

UniValue AsyncRPCOperation_saplingmigration::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    UniValue obj = v.get_obj();
    obj.pushKV("method", "saplingmigration");
    obj.pushKV("target_height", targetHeight_);
    return obj;
}
