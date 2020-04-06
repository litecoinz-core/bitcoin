// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <wallet/asyncrpcoperation_shieldcoinbase.h>

#include <amount.h>
#include <asyncrpcqueue.h>
#include <consensus/upgrades.h>
#include <core_io.h>
#include <init.h>
#include <key_io.h>
#include <net.h>
#include <netbase.h>
#include <policy/policy.h>
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
#include <wallet/paymentdisclosuredb.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <zcash/IncrementalMerkleTree.hpp>
#include <zcashparams.h>

#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <sodium.h>

AsyncRPCOperation_shieldcoinbase::AsyncRPCOperation_shieldcoinbase(
        const JSONRPCRequest& request,
        boost::optional<TransactionBuilder> builder,
        CMutableTransaction contextualTx,
        std::vector<ShieldCoinbaseUTXO> tInputs,
        std::string zOutput,
        CAmount fee,
        UniValue contextInfo) :
        request_(request), tx_(MakeTransactionRef(std::move(contextualTx))), t_inputs_(tInputs), z_output_(zOutput), fee_(fee), contextinfo_(contextInfo)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();
    auto locked_chain = pwallet->chain().lock();

    assert(fee_ >= 0);
    assert(contextualTx.nVersion >= 2);  // transaction format version must support vJoinSplit

    if (fee_ < 0 || fee_ > MAX_MONEY) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee is out of range");
    }

    if (tInputs.size() == 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Empty inputs");
    }

    //  Check the destination address is valid for this network i.e. not testnet being used on mainnet
    auto address = DecodePaymentAddress(z_output_);
    if (!IsValidPaymentAddress(address)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
    }

    isUsingBuilder_ = false;
    if (builder) {
        isUsingBuilder_ = true;
        builder_ = builder.get();
    }

    // Log the context info i.e. the call parameters to z_shieldcoinbase
    LogPrint(BCLog::ZRPC, "%s: z_shieldcoinbase initialized (params=%s)\n", getId(), contextInfo.write());

    // Enable payment disclosure if requested
    paymentDisclosureMode = gArgs.GetBoolArg("-paymentdisclosure", false);
}

AsyncRPCOperation_shieldcoinbase::~AsyncRPCOperation_shieldcoinbase() {
}

void AsyncRPCOperation_shieldcoinbase::main() {
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

    std::string s = strprintf("%s: z_shieldcoinbase finished (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", txid=%s)\n", tx_->GetHash().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s",s);

    // !!! Payment disclosure START
    if (success && paymentDisclosureMode && paymentDisclosureData_.size()>0) {
        uint256 txidhash = tx_->GetHash();
        std::shared_ptr<PaymentDisclosureDB> db = PaymentDisclosureDB::sharedInstance();
        for (PaymentDisclosureKeyInfo p : paymentDisclosureData_) {
            p.first.hash = txidhash;
            if (!db->Put(p.first, p.second)) {
                LogPrint(BCLog::PAYMENTDISCLOSURE, "%s: Payment Disclosure: Error writing entry to database for key %s\n", getId(), p.first.ToString());
            } else {
                LogPrint(BCLog::PAYMENTDISCLOSURE, "%s: Payment Disclosure: Successfully added entry to database for key %s\n", getId(), p.first.ToString());
            }
        }
    }
    // !!! Payment disclosure END
}

bool AsyncRPCOperation_shieldcoinbase::main_impl() {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();
    auto locked_chain = pwallet->chain().lock();

    CAmount minersFee = fee_;

    CAmount t_inputs_total = 0;
    for (ShieldCoinbaseUTXO & t : t_inputs_) {
        t_inputs_total += t.amount;
    }

    if (t_inputs_total < minersFee) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient coinbase funds, have %s and miners fee is %s",
            FormatMoney(t_inputs_total), FormatMoney(minersFee)));
    }

    // update the transaction with these inputs
    if (isUsingBuilder_) {
        for (ShieldCoinbaseUTXO t : t_inputs_) {
            builder_.AddTransparentInput(COutPoint(t.txid, t.vout), t.script, t.amount);
        }
    } else {
        CMutableTransaction rawTx(*tx_);
        for (ShieldCoinbaseUTXO & t : t_inputs_) {
            CTxIn in(COutPoint(t.txid, t.vout));
            rawTx.vin.push_back(in);
        }
        tx_ = MakeTransactionRef(std::move(rawTx));
    }

    CAmount sendAmount = t_inputs_total - minersFee;

    LogPrint(BCLog::ZRPC, "%s: spending %s to send %s with fee %s\n", getId(), FormatMoney(t_inputs_total), FormatMoney(sendAmount), FormatMoney(minersFee));
    LogPrint(BCLog::ZRPC, "%s: transparent input: %s (to choose from)\n", getId(), FormatMoney(t_inputs_total));
    LogPrint(BCLog::ZRPC, "%s: private output: %s\n", getId(), FormatMoney(sendAmount));
    LogPrint(BCLog::ZRPC, "%s: fee: %s\n", getId(), FormatMoney(minersFee));

    /**
     * Sprout not involved, so we just use the TransactionBuilder and we're done.
     * We added the transparent inputs to the builder earlier.
     */
    if (isUsingBuilder_) {
        builder_.SetFee(minersFee);

        // Sending from a t-address, which we don't have an ovk for. Instead,
        // generate a common one from the HD seed. This ensures the data is
        // recoverable, while keeping it logically separate from the ZIP 32
        // Sapling key hierarchy, which the user might not be using.
        HDSeed seed = pwallet->GetZecHDSeedForRPC(pwallet);
        uint256 ovk = ovkForShieldingFromTaddr(seed);

        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(pwallet);

        // Send all value to the target z-addr
        auto zaddr = DecodePaymentAddress(z_output_);
        libzcash::SaplingPaymentAddress address = boost::get<libzcash::SaplingPaymentAddress>(zaddr);
        builder_.SendChangeTo(address, ovk);

        // Build the transaction
        tx_ = builder_.Build().GetTxOrThrow();

        UniValue sendResult = SendTransaction(tx_, pwallet, testmode);
        set_result(sendResult);

        return true;
    }
    else
    {
        // Grab the current consensus branch ID
        {
            LOCK(cs_main);
            consensusBranchId_ = CurrentEpochBranchId(::ChainActive().Height() + 1, Params().GetConsensus());
        }

        // Prepare raw transaction to handle JoinSplits
        CMutableTransaction mtx(*tx_);
        crypto_sign_keypair(joinSplitPubKey_.begin(), joinSplitPrivKey_);
        mtx.joinSplitPubKey = joinSplitPubKey_;
        tx_ = MakeTransactionRef(std::move(mtx));

        // Create joinsplits, where each output represents a zaddr recipient.
        UniValue obj(UniValue::VOBJ);
        ShieldCoinbaseJSInfo info;
        info.vpub_old = sendAmount;
        info.vpub_new = 0;
        auto zaddr = DecodePaymentAddress(z_output_);
        libzcash::SproutPaymentAddress address = boost::get<libzcash::SproutPaymentAddress>(zaddr);
        libzcash::JSOutput jso = libzcash::JSOutput(address, sendAmount);
        info.vjsout.push_back(jso);
        obj = perform_joinsplit(info);

        auto txAndResult = SignSendRawTransaction(obj, pwallet, testmode);
        tx_ = txAndResult.first;
        set_result(txAndResult.second);
        return true;
    }
}

UniValue AsyncRPCOperation_shieldcoinbase::perform_joinsplit(ShieldCoinbaseJSInfo& info)
{
    std::vector<boost::optional<SproutWitness>> witnesses;
    uint256 anchor;
    {
        LOCK(cs_main);
        anchor = ::ChainstateActive().CoinsTip().GetBestAnchor(SPROUT);    // As there are no inputs, ask the wallet for the best anchor
    }
    return perform_joinsplit(info, witnesses, anchor);
}

UniValue AsyncRPCOperation_shieldcoinbase::perform_joinsplit(ShieldCoinbaseJSInfo& info, std::vector<SproutOutPoint> & outPoints)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();
    auto locked_chain = pwallet->chain().lock();

    std::vector<boost::optional<SproutWitness>> witnesses;
    uint256 anchor;
    {
        LOCK(cs_main);
        pwallet->GetSproutNoteWitnesses(outPoints, witnesses, anchor);
    }
    return perform_joinsplit(info, witnesses, anchor);
}

UniValue AsyncRPCOperation_shieldcoinbase::perform_joinsplit(
    ShieldCoinbaseJSInfo & info,
    std::vector<boost::optional<SproutWitness>> witnesses,
    uint256 anchor)
{
    if (anchor.IsNull()) {
        throw std::runtime_error("anchor is null");
    }

    // Make sure there are two inputs and two outputs
    while (info.vjsin.size() < ZC_NUM_JS_INPUTS) {
        info.vjsin.push_back(libzcash::JSInput());
    }

    while (info.vjsout.size() < ZC_NUM_JS_OUTPUTS) {
        info.vjsout.push_back(libzcash::JSOutput());
    }

    if (info.vjsout.size() != ZC_NUM_JS_INPUTS || info.vjsin.size() != ZC_NUM_JS_OUTPUTS) {
        throw std::runtime_error("unsupported joinsplit input/output counts");
    }

    CMutableTransaction mtx(*tx_);

    LogPrint(BCLog::ZRPC, "%s: creating joinsplit at index %d (vpub_old=%s, vpub_new=%s, in[0]=%s, in[1]=%s, out[0]=%s, out[1]=%s)\n",
             getId(),
             tx_->vJoinSplit.size(),
             FormatMoney(info.vpub_old), FormatMoney(info.vpub_new),
             FormatMoney(info.vjsin[0].note.value()), FormatMoney(info.vjsin[1].note.value()),
             FormatMoney(info.vjsout[0].value), FormatMoney(info.vjsout[1].value));

    // Generate the proof, this can take over a minute.
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs {info.vjsin[0], info.vjsin[1]};
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs {info.vjsout[0], info.vjsout[1]};
    std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
    std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;

    uint256 esk; // payment disclosure - secret

    assert(mtx.fOverwintered && (mtx.nVersion >= SAPLING_TX_VERSION));
    JSDescription jsdesc = JSDescription::Randomized(
            *pzcashParams,
            joinSplitPubKey_,
            anchor,
            inputs,
            outputs,
            inputMap,
            outputMap,
            info.vpub_old,
            info.vpub_new,
            !this->testmode,
            &esk); // parameter expects pointer to esk, so pass in address
    {
        auto verifier = libzcash::ProofVerifier::Strict();
        if (!(jsdesc.Verify(*pzcashParams, verifier, joinSplitPubKey_))) {
            throw std::runtime_error("error verifying joinsplit");
        }
    }

    mtx.vJoinSplit.push_back(jsdesc);

    // Empty output script.
    CScript scriptCode;
    CTransaction signTx(mtx);

    SigVersion sigversion = SigVersion::BASE;
    if (signTx.fOverwintered) {
        if (signTx.nVersionGroupId == SAPLING_VERSION_GROUP_ID || signTx.nVersionGroupId == ALPHERATZ_VERSION_GROUP_ID) {
            sigversion = SigVersion::SAPLING_V0;
        } else {
            sigversion = SigVersion::OVERWINTER;
        }
    }
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, sigversion, consensusBranchId_);

    // Add the signature
    if (!(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
            dataToBeSigned.begin(), 32,
            joinSplitPrivKey_
            ) == 0))
    {
        throw std::runtime_error("crypto_sign_detached failed");
    }

    // Sanity check
    if (!(crypto_sign_verify_detached(&mtx.joinSplitSig[0],
            dataToBeSigned.begin(), 32,
            mtx.joinSplitPubKey.begin()
            ) == 0))
    {
        throw std::runtime_error("crypto_sign_verify_detached failed");
    }

    CTransactionRef rawTx = MakeTransactionRef(std::move(mtx));
    tx_ = rawTx;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;

    std::string encryptedNote1;
    std::string encryptedNote2;
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x00);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[0];
        ss2 << jsdesc.h_sig(*pzcashParams, joinSplitPubKey_);

        encryptedNote1 = HexStr(ss2.begin(), ss2.end());
    }
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x01);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[1];
        ss2 << jsdesc.h_sig(*pzcashParams, joinSplitPubKey_);

        encryptedNote2 = HexStr(ss2.begin(), ss2.end());
    }

    UniValue arrInputMap(UniValue::VARR);
    UniValue arrOutputMap(UniValue::VARR);
    for (size_t i = 0; i < ZC_NUM_JS_INPUTS; i++) {
        arrInputMap.push_back(static_cast<uint64_t>(inputMap[i]));
    }
    for (size_t i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        arrOutputMap.push_back(static_cast<uint64_t>(outputMap[i]));
    }

    // !!! Payment disclosure START
    unsigned char buffer[32] = {0};
    memcpy(&buffer[0], &joinSplitPrivKey_[0], 32); // private key in first half of 64 byte buffer
    std::vector<unsigned char> vch(&buffer[0], &buffer[0] + 32);
    uint256 joinSplitPrivKey = uint256(vch);
    size_t js_index = tx_->vJoinSplit.size() - 1;
    uint256 placeholder;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        uint8_t mapped_index = outputMap[i];
        // placeholder for txid will be filled in later when tx has been finalized and signed.
        PaymentDisclosureKey pdKey = {placeholder, js_index, mapped_index};
        libzcash::JSOutput output = outputs[mapped_index];
        libzcash::SproutPaymentAddress zaddr = output.addr;  // randomized output
        PaymentDisclosureInfo pdInfo = {PAYMENT_DISCLOSURE_VERSION_EXPERIMENTAL, esk, joinSplitPrivKey, zaddr};
        paymentDisclosureData_.push_back(PaymentDisclosureKeyInfo(pdKey, pdInfo));

        LogPrint(BCLog::PAYMENTDISCLOSURE, "%s: Payment Disclosure: js=%d, n=%d, zaddr=%s\n", getId(), js_index, int(mapped_index), EncodePaymentAddress(zaddr));
    }
    // !!! Payment disclosure END

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("encryptednote1", encryptedNote1);
    obj.pushKV("encryptednote2", encryptedNote2);
    obj.pushKV("rawtxn", HexStr(ss.begin(), ss.end()));
    obj.pushKV("inputmap", arrInputMap);
    obj.pushKV("outputmap", arrOutputMap);
    return obj;
}

/**
 * Override getStatus() to append the operation's input parameters to the default status object.
 */
UniValue AsyncRPCOperation_shieldcoinbase::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }

    UniValue obj = v.get_obj();
    obj.pushKV("method", "z_shieldcoinbase");
    obj.pushKV("params", contextinfo_ );
    return obj;
}

