// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <core_io.h>
#include <key_io.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/standard.h>
#include <sync.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>
#include <wallet/paymentdisclosure.h>
#include <wallet/paymentdisclosuredb.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <zcash/Note.hpp>
#include <zcash/NoteEncryption.hpp>
#include <zcashparams.h>

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

/**
 * RPC call to generate a payment disclosure
 */
UniValue z_getpaymentdisclosure(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

            RPCHelpMan{"z_getpaymentdisclosure",
                "\nGenerate a payment disclosure for a given joinsplit output.\n",
                {
                    {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                    {"js_index", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                    {"output_index", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                },
                RPCResult{
            "\"paymentdisclosure\"  (string) Hex data string, with \"zpd:\" prefix.\n"
                },
                RPCExamples{
            HelpExampleCli("z_getpaymentdisclosure", "\"96f12882450429324d5f3b48630e3168220e49ab7b0f066e5c2935a6b88bb0f2\" 0 0 \"refund\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("z_getpaymentdisclosure", "\"96f12882450429324d5f3b48630e3168220e49ab7b0f066e5c2935a6b88bb0f2\", 0, 0, \"refund\"")
                },
            }.Check(request);

    bool fEnablePaymentDisclosure = gArgs.GetBoolArg("-paymentdisclosure", false);

    if (!fEnablePaymentDisclosure) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: payment disclosure is disabled.");
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Check wallet knows about txid
    std::string txid = request.params[0].get_str();
    uint256 hash;
    hash.SetHex(txid);

    CTransactionRef tx;
    uint256 hashBlock;

    // Check txid has been seen
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    }

    // Check tx has been confirmed
    if (hashBlock.IsNull()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Transaction has not been confirmed yet");
    }

    // Check is mine
    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Transaction does not belong to the wallet");
    }
    const CWalletTx& wtx = pwallet->mapWallet.at(hash);

    // Check if shielded tx
    if (wtx.tx->vJoinSplit.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Transaction is not a shielded transaction");
    }

    // Check js_index
    size_t js_index = request.params[1].get_int();
    if ((int)js_index < 0 || js_index >= wtx.tx->vJoinSplit.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid js_index");
    }

    // Check output_index
    int output_index = request.params[2].get_int();
    if (output_index < 0 || output_index >= ZC_NUM_JS_OUTPUTS) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output_index");
    }

    // Get message if it exists
    std::string msg;
    if (!request.params[4].isNull()) {
        msg = request.params[3].get_str();
    }

    // Create PaymentDisclosureKey
    PaymentDisclosureKey key = {hash, js_index, (uint8_t)output_index};

    // TODO: In future, perhaps init the DB in init.cpp
    std::shared_ptr<PaymentDisclosureDB> db = PaymentDisclosureDB::sharedInstance();
    PaymentDisclosureInfo info;
    if (!db->Get(key, info)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find payment disclosure info for the given joinsplit output");
    }

    PaymentDisclosure pd(wtx.tx->joinSplitPubKey, key, info, msg);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << pd;
    std::string strHex = HexStr(ss.begin(), ss.end());
    return PAYMENT_DISCLOSURE_BLOB_STRING_PREFIX + strHex;
}

/**
 * RPC call to validate a payment disclosure data blob.
 */
UniValue z_validatepaymentdisclosure(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

            RPCHelpMan{"z_validatepaymentdisclosure",
                "\nValidates a payment disclosure.\n",
                {
                    {"paymentdisclosure", RPCArg::Type::STR, RPCArg::Optional::NO, "Hex data string, with \"zpd:\" prefix."},
                },
                RPCResults{},
                RPCExamples{
            HelpExampleCli("z_validatepaymentdisclosure", "\"zpd:706462ff004c561a0447ba2ec51184e6c204...\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("z_validatepaymentdisclosure", "\"zpd:706462ff004c561a0447ba2ec51184e6c204...\"")
                },
            }.Check(request);

    bool fEnablePaymentDisclosure = gArgs.GetBoolArg("-paymentdisclosure", false);

    if (!fEnablePaymentDisclosure) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: payment disclosure is disabled.");
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Verify the payment disclosure input begins with "zpd:" prefix.
    std::string strInput = request.params[0].get_str();
    size_t pos = strInput.find(PAYMENT_DISCLOSURE_BLOB_STRING_PREFIX);
    if (pos != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, payment disclosure prefix not found.");
    }
    std::string hexInput = strInput.substr(strlen(PAYMENT_DISCLOSURE_BLOB_STRING_PREFIX));
    if (!IsHex(hexInput))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected payment disclosure data in hexadecimal format.");
    }

    // Unserialize the payment disclosure data into an object
    PaymentDisclosure pd;
    CDataStream ss(ParseHex(hexInput), SER_NETWORK, PROTOCOL_VERSION);
    try {
        ss >> pd;
        // too much data is ignored, but if not enough data, exception of type ios_base::failure is thrown,
        // CBaseDataStream::read(): end of data: iostream error
    } catch (const std::exception &e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, payment disclosure data is malformed.");
    }

    if (pd.payload.marker != PAYMENT_DISCLOSURE_PAYLOAD_MAGIC_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, payment disclosure marker not found.");
    }

    if (pd.payload.version != PAYMENT_DISCLOSURE_VERSION_EXPERIMENTAL) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Payment disclosure version is unsupported.");
    }

    uint256 hash = pd.payload.txid;
    CTransactionRef tx;
    uint256 hashBlock;
    // Check if we have seen the transaction
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    }

    // Check if the transaction has been confirmed
    if (hashBlock.IsNull()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Transaction has not been confirmed yet");
    }

    // Check if shielded tx
    if (tx->vJoinSplit.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Transaction is not a shielded transaction");
    }

    UniValue errs(UniValue::VARR);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", pd.payload.txid.ToString());

    // Check js_index
    if (pd.payload.js >= tx->vJoinSplit.size()) {
        errs.push_back("Payment disclosure refers to an invalid joinsplit index");
    }
    o.pushKV("jsIndex", pd.payload.js);

    if ((int8_t)pd.payload.n < 0 || pd.payload.n >= ZC_NUM_JS_OUTPUTS) {
        errs.push_back("Payment disclosure refers to an invalid output index");
    }
    o.pushKV("outputIndex", pd.payload.n);
    o.pushKV("version", pd.payload.version);
    o.pushKV("onetimePrivKey", pd.payload.esk.ToString());
    o.pushKV("message", pd.payload.message);
    o.pushKV("joinSplitPubKey", tx->joinSplitPubKey.ToString());

    // Verify the payment disclosure was signed using the same key as the transaction i.e. the joinSplitPrivKey.
    uint256 dataToBeSigned = SerializeHash(pd.payload, SER_GETHASH, 0);
    bool sigVerified = (crypto_sign_verify_detached(pd.payloadSig.data(),
        dataToBeSigned.begin(), 32,
        tx->joinSplitPubKey.begin()) == 0);
    o.pushKV("signatureVerified", sigVerified);
    if (!sigVerified) {
        errs.push_back("Payment disclosure signature does not match transaction signature");
    }

    // Check the payment address is valid
    libzcash::SproutPaymentAddress zaddr = pd.payload.zaddr;
    {
        o.pushKV("paymentAddress", EncodePaymentAddress(zaddr));

        try {
            // Decrypt the note to get value and memo field
            JSDescription jsdesc = tx->vJoinSplit[pd.payload.js];
            uint256 h_sig = jsdesc.h_sig(*pzcashParams, tx->joinSplitPubKey);

            ZCPaymentDisclosureNoteDecryption decrypter;

            ZCNoteEncryption::Ciphertext ciphertext = jsdesc.ciphertexts[pd.payload.n];

            uint256 pk_enc = zaddr.pk_enc;
            auto plaintext = decrypter.decryptWithEsk(ciphertext, pk_enc, pd.payload.esk, h_sig, pd.payload.n);

            CDataStream ssPlain(SER_NETWORK, PROTOCOL_VERSION);
            ssPlain << plaintext;
            libzcash::SproutNotePlaintext npt;
            ssPlain >> npt;

            std::string memoHexString = HexStr(npt.memo().data(), npt.memo().data() + npt.memo().size());
            o.pushKV("memo", memoHexString);
            o.pushKV("value", ValueFromAmount(npt.value()));

            // Check the blockchain commitment matches decrypted note commitment
            uint256 cm_blockchain =  jsdesc.commitments[pd.payload.n];
            libzcash::SproutNote note = npt.note(zaddr);
            uint256 cm_decrypted = note.cm();
            bool cm_match = (cm_decrypted == cm_blockchain);
            o.pushKV("commitmentMatch", cm_match);
            if (!cm_match) {
                errs.push_back("Commitment derived from payment disclosure does not match blockchain commitment");
            }
        } catch (const std::exception &e) {
            errs.push_back(std::string("Error while decrypting payment disclosure note: ") + std::string(e.what()) );
        }
    }

    bool isValid = errs.empty();
    o.pushKV("valid", isValid);
    if (!isValid) {
        o.pushKV("errors", errs);
    }

    return o;
}
