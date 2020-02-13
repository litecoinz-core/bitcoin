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
        TransactionBuilder builder,
        CMutableTransaction contextualTx,
        std::vector<ShieldCoinbaseUTXO> inputs,
        std::string toAddress,
        CAmount fee,
        UniValue contextInfo) :
        request_(request), builder_(builder), tx_(MakeTransactionRef(std::move(contextualTx))), inputs_(inputs), fee_(fee), contextinfo_(contextInfo)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();
    auto locked_chain = pwallet->chain().lock();

    assert(contextualTx.nVersion >= 2);  // transaction format version must support vJoinSplit

    if (fee < 0 || fee > MAX_MONEY) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee is out of range");
    }

    if (inputs.size() == 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Empty inputs");
    }

    //  Check the destination address is valid for this network i.e. not testnet being used on mainnet
    auto address = DecodePaymentAddress(toAddress);
    if (IsValidPaymentAddress(address)) {
        tozaddr_ = address;
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid to address");
    }

    // Log the context info
    if (LogAcceptCategory(BCLog::ZRPCUNSAFE)) {
        LogPrint(BCLog::ZRPCUNSAFE, "%s: z_shieldcoinbase initialized (context=%s)\n", getId(), contextInfo.write());
    } else {
        LogPrint(BCLog::ZRPC, "%s: z_shieldcoinbase initialized\n", getId());
    }

    // Lock UTXOs
    lock_utxos(pwallet);

    // Enable payment disclosure if requested
    paymentDisclosureMode = gArgs.GetBoolArg("-paymentdisclosure", false);
}

AsyncRPCOperation_shieldcoinbase::~AsyncRPCOperation_shieldcoinbase() {
}

void AsyncRPCOperation_shieldcoinbase::main() {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();

    if (isCancelled()) {
        unlock_utxos(pwallet); // clean up
        return;
    }

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

    unlock_utxos(pwallet); // clean up

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
    CAmount minersFee = fee_;
    CAmount targetAmount = 0;

    for (ShieldCoinbaseUTXO & utxo : inputs_) {
        targetAmount += utxo.amount;
    }

    if (targetAmount <= minersFee) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient coinbase funds, have %s and miners fee is %s",
            FormatMoney(targetAmount), FormatMoney(minersFee)));
    }

    CAmount sendAmount = targetAmount - minersFee;
    LogPrint(BCLog::ZRPC, "%s: spending %s to shield %s with fee %s\n",
            getId(), FormatMoney(targetAmount), FormatMoney(sendAmount), FormatMoney(minersFee));

    return boost::apply_visitor(ShieldToAddress(this, sendAmount, request_), tozaddr_);
}

bool ShieldToAddress::operator()(const libzcash::SproutPaymentAddress &zaddr) const {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();

    // update the transaction with these inputs
    CMutableTransaction rawTx(*m_op->tx_);
    for (ShieldCoinbaseUTXO & t : m_op->inputs_) {
        CTxIn in(COutPoint(t.txid, t.vout));
        rawTx.vin.push_back(in);
    }
    m_op->tx_ = MakeTransactionRef(std::move(rawTx));

    // Prepare raw transaction to handle JoinSplits
    CMutableTransaction mtx(*m_op->tx_);
    crypto_sign_keypair(m_op->joinSplitPubKey_.begin(), m_op->joinSplitPrivKey_);
    mtx.joinSplitPubKey = m_op->joinSplitPubKey_;
    m_op->tx_ = MakeTransactionRef(std::move(rawTx));

    // Create joinsplit
    ShieldCoinbaseJSInfo info;
    info.vpub_old = sendAmount;
    info.vpub_new = 0;
    libzcash::JSOutput jso = libzcash::JSOutput(zaddr, sendAmount);
    info.vjsout.push_back(jso);
    UniValue obj = m_op->perform_joinsplit(info);

    auto txAndResult = SignSendRawTransaction(obj, pwallet, m_op->testmode);
    m_op->tx_ = txAndResult.first;
    m_op->set_result(txAndResult.second);
    return true;
}

bool ShieldToAddress::operator()(const libzcash::SaplingPaymentAddress &zaddr) const {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request_);
    CWallet* const pwallet = wallet.get();

    m_op->builder_.SetFee(m_op->fee_);

    // Sending from a t-address, which we don't have an ovk for. Instead,
    // generate a common one from the HD seed. This ensures the data is
    // recoverable, while keeping it logically separate from the ZIP 32
    // Sapling key hierarchy, which the user might not be using.
    HDSeed seed = pwallet->GetZecHDSeedForRPC(pwallet);
    uint256 ovk = ovkForShieldingFromTaddr(seed);

    // Add transparent inputs
    for (auto t : m_op->inputs_) {
        m_op->builder_.AddTransparentInput(COutPoint(t.txid, t.vout), t.scriptPubKey, t.amount);
    }

    // Send all value to the target z-addr
    m_op->builder_.SendChangeTo(zaddr, ovk);

    // Build the transaction
    m_op->tx_ = m_op->builder_.Build().GetTxOrThrow();

    UniValue sendResult = SendTransaction(m_op->tx_, pwallet, m_op->testmode);
    m_op->set_result(sendResult);

    return true;
}

bool ShieldToAddress::operator()(const libzcash::InvalidEncoding& no) const {
    return false;
}

UniValue AsyncRPCOperation_shieldcoinbase::perform_joinsplit(ShieldCoinbaseJSInfo & info) {
    uint32_t consensusBranchId;
    uint256 anchor;
    {
        LOCK(cs_main);
        consensusBranchId = CurrentEpochBranchId(::ChainActive().Height() + 1, Params().GetConsensus());
        anchor = ::ChainstateActive().CoinsTip().GetBestAnchor(SPROUT);
    }

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

    LogPrint(BCLog::ZRPCUNSAFE, "%s: creating joinsplit at index %d (vpub_old=%s, vpub_new=%s, in[0]=%s, in[1]=%s, out[0]=%s, out[1]=%s)\n",
            getId(),
            tx_->vJoinSplit.size(),
            FormatMoney(info.vpub_old), FormatMoney(info.vpub_new),
            FormatMoney(info.vjsin[0].note.value()), FormatMoney(info.vjsin[1].note.value()),
            FormatMoney(info.vjsout[0].value), FormatMoney(info.vjsout[1].value)
            );

    // Generate the proof, this can take over a minute.
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs
            {info.vjsin[0], info.vjsin[1]};
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs
            {info.vjsout[0], info.vjsout[1]};
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
        if (signTx.nVersionGroupId == SAPLING_VERSION_GROUP_ID) {
            sigversion = SigVersion::SAPLING_V0;
        } else {
            sigversion = SigVersion::OVERWINTER;
        }
    }
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, sigversion, consensusBranchId);

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
 * Override getStatus() to append the operation's context object to the default status object.
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

/**
 * Lock input utxos
 */
 void AsyncRPCOperation_shieldcoinbase::lock_utxos(CWallet* const pwallet) {
    LOCK2(cs_main, pwallet->cs_wallet);
    for (auto utxo : inputs_) {
        COutPoint outpt(utxo.txid, utxo.vout);
        pwallet->LockCoin(outpt);
    }
}

/**
 * Unlock input utxos
 */
void AsyncRPCOperation_shieldcoinbase::unlock_utxos(CWallet* const pwallet) {
    LOCK2(cs_main, pwallet->cs_wallet);
    for (auto utxo : inputs_) {
        COutPoint outpt(utxo.txid, utxo.vout);
        pwallet->UnlockCoin(outpt);
    }
}
