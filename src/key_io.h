// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_IO_H
#define BITCOIN_KEY_IO_H

#include <chainparams.h>
#include <key.h>
#include <pubkey.h>
#include <script/standard.h>
#include <zcash/Address.hpp>
#include <zcash/zip32.h>

#include <string>

CKey DecodeSecret(const std::string& str);
std::string EncodeSecret(const CKey& key);

CExtKey DecodeExtKey(const std::string& str);
std::string EncodeExtKey(const CExtKey& extkey);
CExtPubKey DecodeExtPubKey(const std::string& str);
std::string EncodeExtPubKey(const CExtPubKey& extpubkey);

std::string EncodeDestination(const CTxDestination& dest);
CTxDestination DecodeDestination(const std::string& str);
bool IsValidDestinationString(const std::string& str);
bool IsValidDestinationString(const std::string& str, const CChainParams& params);

std::string EncodePaymentAddress(const libzcash::PaymentAddress& address);
libzcash::PaymentAddress DecodePaymentAddress(const std::string& str);
bool IsValidPaymentAddressString(const std::string& str);

std::string EncodeViewingKey(const libzcash::ViewingKey& vk);
libzcash::ViewingKey DecodeViewingKey(const std::string& str);

std::string EncodeSpendingKey(const libzcash::SpendingKey& sk);
libzcash::SpendingKey DecodeSpendingKey(const std::string& str);

#endif // BITCOIN_KEY_IO_H
