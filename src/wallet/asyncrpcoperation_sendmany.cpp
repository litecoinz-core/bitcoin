// Copyright (c) 2016 The Zcash developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <wallet/asyncrpcoperation_sendmany.h>

#include <amount.h>
#include <asyncrpcqueue.h>
#include <consensus/upgrades.h>
#include <core_io.h>
#include <init.h>
#include <key_io.h>
#include <net.h>
#include <netbase.h>
#include <policy/policy.h>
#include <proof_verifier.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <script/interpreter.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>
#include <wallet/asyncrpcoperation_common.h>
#include <wallet/fees.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <zcash/IncrementalMerkleTree.hpp>

#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <sodium.h>

int find_output(UniValue obj, int n) {
    UniValue outputMapValue = find_value(obj, "outputmap");
    if (!outputMapValue.isArray()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing outputmap for JoinSplit operation");
    }

    UniValue outputMap = outputMapValue.get_array();
    assert(outputMap.size() == ZC_NUM_JS_OUTPUTS);
    for (size_t i = 0; i < outputMap.size(); i++) {
        if (outputMap[i].get_int() == n) {
            return i;
        }
    }

    throw std::logic_error("n is not present in outputmap");
}

AsyncRPCOperation_sendmany::AsyncRPCOperation_sendmany(
        CWallet* const pwallet,
        Optional<TransactionBuilder> builder,
        CMutableTransaction contextualTx,
        std::string fromAddress,
        std::vector<SendManyRecipient> tOutputs,
        std::vector<SendManyRecipient> zOutputs,
        int minDepth,
        CAmount fee,
        UniValue contextInfo) :
        pwallet_(pwallet), tx_(MakeTransactionRef(std::move(contextualTx))), fromaddress_(fromAddress), t_outputs_(tOutputs), z_outputs_(zOutputs), mindepth_(minDepth), fee_(fee), contextinfo_(contextInfo)
{
    assert(fee_ >= 0);

    if (minDepth < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be negative");
    }

    if (fromAddress.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "From address parameter missing");
    }

    if (tOutputs.size() == 0 && zOutputs.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No recipients");
    }

    builder_ = builder.get();

    fromtaddr_ = DecodeDestination(fromAddress);
    isfromtaddr_ = IsValidDestination(fromtaddr_);
    isfromzaddr_ = false;

    if (!isfromtaddr_) {
        auto address = DecodePaymentAddress(fromAddress);
        if (IsValidPaymentAddress(address)) {
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!std::visit(HaveSpendingKeyForPaymentAddress(pwallet_), address)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            isfromzaddr_ = true;
            frompaymentaddress_ = address;
            auto sk = std::visit(GetSpendingKeyForPaymentAddress(pwallet_), address);
            spendingkey_ = sk.get();
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address");
        }
    }

    if (isfromzaddr_ && minDepth==0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be zero when sending from zaddr");
    }

    // Log the context info i.e. the call parameters to z_sendmany
    LogPrint(BCLog::ZRPC, "%s: z_sendmany initialized (params=%s)\n", getId(), contextInfo.write());

    // Enable payment disclosure if requested
    paymentDisclosureMode = gArgs.GetBoolArg("-paymentdisclosure", false);
}

AsyncRPCOperation_sendmany::~AsyncRPCOperation_sendmany() {
}

void AsyncRPCOperation_sendmany::main() {
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

    std::string s = strprintf("%s: z_sendmany finished (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", txid=%s)\n", tx_->GetHash().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s",s);
}

struct TxValues {
    CAmount t_inputs_total{0};
    CAmount z_inputs_total{0};
    CAmount t_outputs_total{0};
    CAmount z_outputs_total{0};
    CAmount targetAmount{0};
};

// Notes:
// 1. #1159 Currently there is no limit set on the number of joinsplits, so size of tx could be invalid.
// 2. #1360 Note selection is not optimal
// 3. #1277 Spendable notes are not locked, so an operation running in parallel could also try to use them
bool AsyncRPCOperation_sendmany::main_impl() {
    CWallet* const pwallet = pwallet_;

    assert(isfromtaddr_ != isfromzaddr_);

    bool isSingleZaddrOutput = (t_outputs_.size()==0 && z_outputs_.size()==1);
    bool isMultipleZaddrOutput = (t_outputs_.size()==0 && z_outputs_.size()>=1);
    CAmount minersFee = fee_;
    TxValues txValues;

    // First calculate the target
    for (SendManyRecipient & t : t_outputs_) {
        txValues.t_outputs_total += t.amount;
    }

    for (SendManyRecipient & t : z_outputs_) {
        txValues.z_outputs_total += t.amount;
    }

    CAmount sendAmount = txValues.z_outputs_total + txValues.t_outputs_total;
    txValues.targetAmount = sendAmount + minersFee;

    // When spending coinbase utxos, you can only specify a single zaddr as the change must go somewhere
    // and if there are multiple zaddrs, we don't know where to send it.
    if (isfromtaddr_) {
        if (isSingleZaddrOutput) {
            bool b = find_utxos(txValues);
            if (!b) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no UTXOs found for taddr from address.");
            }
        } else {
            bool b = find_utxos(txValues);
            if (!b) {
                if (isMultipleZaddrOutput) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find any UTXOs to spend.");
                } else {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find any UTXOs to spend.");
                }
            }
        }
    }

    if (isfromzaddr_ && !find_unspent_notes()) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no unspent notes found for zaddr from address.");
    }

    for (auto t : z_sapling_inputs_) {
        txValues.z_inputs_total += t.note.value();
    }

    assert(!isfromtaddr_ || txValues.z_inputs_total == 0);
    assert(!isfromzaddr_ || txValues.t_inputs_total == 0);

    if (isfromzaddr_ && (txValues.z_inputs_total < txValues.targetAmount)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient shielded funds, have %s, need %s",
            FormatMoney(txValues.z_inputs_total), FormatMoney(txValues.targetAmount)));
    }

    LogPrint(BCLog::ZRPC, "%s: spending %s to send %s with fee %s\n",
            getId(), FormatMoney(txValues.targetAmount), FormatMoney(sendAmount), FormatMoney(minersFee));
    LogPrint(BCLog::ZRPC, "%s: transparent input: %s (to choose from)\n", getId(), FormatMoney(txValues.t_inputs_total));
    LogPrint(BCLog::ZRPC, "%s: private input: %s (to choose from)\n", getId(), FormatMoney(txValues.z_inputs_total));
    LogPrint(BCLog::ZRPC, "%s: transparent output: %s\n", getId(), FormatMoney(txValues.t_outputs_total));
    LogPrint(BCLog::ZRPC, "%s: private output: %s\n", getId(), FormatMoney(txValues.z_outputs_total));
    LogPrint(BCLog::ZRPC, "%s: fee: %s\n", getId(), FormatMoney(minersFee));

    builder_.SetFee(minersFee);

    // Get various necessary keys
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 ovk;
    if (isfromzaddr_) {
        auto sk = std::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
        expsk = sk.expsk;
        ovk = expsk.full_viewing_key().ovk;
    } else {
        // Sending from a t-address, which we don't have an ovk for. Instead,
        // generate a common one from the HD seed. This ensures the data is
        // recoverable, while keeping it logically separate from the ZIP 32
        // Sapling key hierarchy, which the user might not be using.
        HDSeed seed = pwallet->GetZecHDSeedForRPC(pwallet);
        ovk = ovkForShieldingFromTaddr(seed);
    }

    // Set change address if we are using transparent funds
    // TODO: Should we just use fromtaddr_ as the change address?
    ReserveDestination reservedest(pwallet);
    if (isfromtaddr_) {
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);

        EnsureWalletIsUnlocked(pwallet);
        CTxDestination changeDest;
        const OutputType change_type = pwallet->GetDefaultAddressType();
        bool ret = reservedest.GetReservedDestination(change_type, changeDest, true);
        if (!ret)
        {
            // should never fail, as we just unlocked
            throw JSONRPCError(
                RPC_WALLET_KEYPOOL_RAN_OUT,
                "Could not generate a taddr to use as a change address");
        }
        builder_.SendChangeTo(changeDest);
    }

    // Select Sapling notes
    std::vector<SaplingOutPoint> ops;
    std::vector<libzcash::SaplingNote> notes;
    CAmount sum = 0;
    for (auto t : z_sapling_inputs_) {
        ops.push_back(t.op);
        notes.push_back(t.note);
        sum += t.note.value();
        if (sum >= txValues.targetAmount) {
            break;
        }
    }

    // Fetch Sapling anchor and witnesses
    uint256 anchor;
    std::vector<Optional<SaplingWitness>> witnesses;
    {
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);
        pwallet->GetSaplingNoteWitnesses(ops, witnesses, anchor);
    }

    // Add Sapling spends
    for (size_t i = 0; i < notes.size(); i++) {
        if (!witnesses[i]) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Missing witness for Sapling note");
        }
        builder_.AddSaplingSpend(expsk, notes[i], anchor, witnesses[i].get());
    }

    // Add Sapling outputs
    for (auto r : z_outputs_) {
        auto address = r.address;
        auto value = r.amount;
        auto hexMemo = r.memo;

        auto addr = DecodePaymentAddress(address);
        assert(std::get_if<libzcash::SaplingPaymentAddress>(&addr) != nullptr);
        auto to = std::get<libzcash::SaplingPaymentAddress>(addr);

        auto memo = get_memo_from_hex_string(hexMemo);

        builder_.AddSaplingOutput(ovk, to, value, memo);
    }

    // Add transparent outputs
    for (auto r : t_outputs_) {
        auto outputAddress = r.address;
        auto amount = r.amount;

        auto address = DecodeDestination(outputAddress);
        builder_.AddTransparentOutput(address, amount);
    }

    // Build the transaction
    tx_ = builder_.Build().GetTxOrThrow();

    UniValue sendResult = SendTransaction(tx_, pwallet, fee_, testmode);
    set_result(sendResult);

    return true;
}

bool AsyncRPCOperation_sendmany::find_utxos(TxValues& txValues)
{
    CWallet* const pwallet = pwallet_;

    std::set<CTxDestination> destinations;
    destinations.insert(fromtaddr_);

    {
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);
        pwallet->AvailableCoins(*locked_chain, t_inputs_);
    }

    if (t_inputs_.empty()) return false;

    // sort in ascending order, so smaller utxos appear first
    std::sort(t_inputs_.begin(), t_inputs_.end(), [](const COutput& i, const COutput& j) -> bool {
        return i.Value() < j.Value();
    });

    // Load transparent inputs
    load_inputs(txValues);

    return t_inputs_.size() > 0;
}

bool AsyncRPCOperation_sendmany::load_inputs(TxValues& txValues)
{
    CWallet* const pwallet = pwallet_;

    // If from address is a taddr, select UTXOs to spend
    CAmount selectedUTXOAmount = 0;
    // Get dust threshold
    CKey secret;
    secret.MakeNewKey(true);
    CScript scriptPubKey = GetScriptForDestination(PKHash(secret.GetPubKey()));
    CTxOut out(CAmount(1), scriptPubKey);
    CAmount dustThreshold = GetDustThreshold(out, GetDiscardRate(*pwallet));
    CAmount dustChange = -1;

    std::vector<COutput> selectedTInputs;
    for (const COutput& out : t_inputs_) {
        selectedUTXOAmount += out.Value();
        selectedTInputs.emplace_back(out);
        if (selectedUTXOAmount >= txValues.targetAmount) {
            // Select another utxo if there is change less than the dust threshold.
            dustChange = selectedUTXOAmount - txValues.targetAmount;
            if (dustChange == 0 || dustChange >= dustThreshold) {
                break;
            }
        }
    }

    t_inputs_ = selectedTInputs;
    txValues.t_inputs_total = selectedUTXOAmount;

    if (txValues.t_inputs_total < txValues.targetAmount) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient transparent funds, have %s, need %s",
                FormatMoney(txValues.t_inputs_total), FormatMoney(txValues.targetAmount)));
    }

    // If there is transparent change, is it valid or is it dust?
    if (dustChange < dustThreshold && dustChange != 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient transparent funds, have %s, need %s more to avoid creating invalid change output %s (dust threshold is %s)",
                FormatMoney(txValues.t_inputs_total), FormatMoney(dustThreshold - dustChange), FormatMoney(dustChange), FormatMoney(dustThreshold)));
    }

    // update the transaction with these inputs
    for (const auto& out : t_inputs_) {
        const CTxOut& txOut = out.tx->tx->vout[out.i];
        builder_.AddTransparentInput(COutPoint(out.tx->GetHash(), out.i), txOut.scriptPubKey, txOut.nValue);
    }
    return true;
}

bool AsyncRPCOperation_sendmany::find_unspent_notes()
{
    CWallet* const pwallet = pwallet_;

    std::vector<SaplingNoteEntry> saplingEntries;
    {
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);
        pwallet->GetFilteredNotes(*locked_chain, saplingEntries, fromaddress_, mindepth_);
    }

    for (auto entry : saplingEntries) {
        z_sapling_inputs_.push_back(entry);
        std::string data(entry.memo.begin(), entry.memo.end());
        LogPrint(BCLog::ZRPC, "%s: found unspent Sapling note (txid=%s, vShieldedSpend=%d, amount=%s, memo=%s)\n",
            getId(),
            entry.op.hash.ToString().substr(0, 10),
            entry.op.n,
            FormatMoney(entry.note.value()),
            HexStr(data).substr(0, 10));
    }

    if (z_sapling_inputs_.empty()) {
        return false;
    }

    // sort in descending order, so big notes appear first
    std::sort(z_sapling_inputs_.begin(), z_sapling_inputs_.end(),
        [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
            return i.note.value() > j.note.value();
        });

    return true;
}

std::array<unsigned char, ZC_MEMO_SIZE> AsyncRPCOperation_sendmany::get_memo_from_hex_string(std::string s) {
    // initialize to default memo (no_memo), see section 5.5 of the protocol spec
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};
    return memo;
}

/**
 * Override getStatus() to append the operation's input parameters to the default status object.
 */
UniValue AsyncRPCOperation_sendmany::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }

    UniValue obj = v.get_obj();
    obj.pushKV("method", "z_sendmany");
    obj.pushKV("params", contextinfo_ );
    return obj;
}

