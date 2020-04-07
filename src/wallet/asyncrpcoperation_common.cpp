// Copyright (c) 2019 The Zcash developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/asyncrpcoperation_common.h>

#include <core_io.h>
#include <init.h>
#include <policy/policy.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <consensus/validation.h>

extern UniValue signrawtransactionwithwallet(const JSONRPCRequest& request);

UniValue SendTransaction(CTransactionRef& tx, CWallet* const pwallet, bool testmode) {
    mapValue_t mapValue;
    UniValue o(UniValue::VOBJ);

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    if (GetTransactionWeight(*tx) > MAX_STANDARD_TX_WEIGHT)
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction too large");
    }

    // Send the transaction
    if (!testmode) {
        pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */, true);
        o.pushKV("txid", tx->GetHash().GetHex());
    } else {
        // Test mode does not send the transaction to the network.
        o.pushKV("test", 1);
        o.pushKV("txid", tx->GetHash().GetHex());
        o.pushKV("hex", EncodeHexTx(*tx));
    }
    return o;
}

std::pair<CTransactionRef, UniValue> SignSendRawTransaction(UniValue obj, CWallet* const pwallet, bool testmode) {
    // Sign the raw transaction
    UniValue rawtxnValue = find_value(obj, "rawtxn");
    if (rawtxnValue.isNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for raw transaction");
    }
    std::string rawtxn = rawtxnValue.get_str();
    UniValue params = UniValue(UniValue::VARR);
    params.push_back(rawtxn);

    JSONRPCRequest request;
    request.params = params;
    request.fHelp = false;

    UniValue signResultValue = signrawtransactionwithwallet(request);
    UniValue signResultObject = signResultValue.get_obj();
    UniValue completeValue = find_value(signResultObject, "complete");
    bool complete = completeValue.get_bool();
    if (!complete) {
        // TODO: #1366 Maybe get "errors" and print array vErrors into a string
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Failed to sign transaction");
    }

    UniValue hexValue = find_value(signResultObject, "hex");
    if (hexValue.isNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for signed transaction");
    }

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hexValue.get_str(), true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    UniValue sendResult = SendTransaction(tx, pwallet, testmode);

    return std::make_pair(tx, sendResult);
}
