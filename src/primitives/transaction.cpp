// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

std::string SproutOutPoint::ToString() const
{
    return strprintf("SproutOutPoint(%s, %d, %d)", hash.ToString().substr(0,10), js, n);
}

std::string SaplingOutPoint::ToString() const
{
    return strprintf("SaplingOutPoint(%s, %u)", hash.ToString().substr(0, 10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::SPROUT_MIN_CURRENT_VERSION), fOverwintered(false), nVersionGroupId(0), nLockTime(0), nExpiryHeight(0), valueBalance(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nLockTime(tx.nLockTime), nExpiryHeight(tx.nExpiryHeight), valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput), vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig), bindingSig(tx.bindingSig) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : vin(), vout(), nVersion(CTransaction::SPROUT_MIN_CURRENT_VERSION), fOverwintered(false), nVersionGroupId(0), nLockTime(0), nExpiryHeight(0), valueBalance(0), vShieldedSpend(), vShieldedOutput(), vJoinSplit(), joinSplitPubKey(), joinSplitSig(), bindingSig(), hash{}, m_witness_hash{} {}

CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nLockTime(tx.nLockTime), nExpiryHeight(tx.nExpiryHeight), valueBalance(tx.valueBalance), vShieldedSpend(std::move(tx.vShieldedSpend)), vShieldedOutput(std::move(tx.vShieldedOutput)), vJoinSplit(std::move(tx.vJoinSplit)), joinSplitPubKey(std::move(tx.joinSplitPubKey)), joinSplitSig(std::move(tx.joinSplitSig)), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nLockTime(tx.nLockTime), nExpiryHeight(tx.nExpiryHeight), valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput), vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig), bindingSig(tx.bindingSig), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    if (valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -valueBalance;

        if (!MoneyRange(-valueBalance) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    for (std::vector<JSDescription>::const_iterator it(vJoinSplit.begin()); it != vJoinSplit.end(); ++it)
    {
        // NB: vpub_old "takes" money from the transparent value pool just as outputs do
        nValueOut += it->vpub_old;

        if (!MoneyRange(it->vpub_old) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    return nValueOut;
}

CAmount CTransaction::GetShieldedValueIn() const
{
    CAmount nValue = 0;

    if (valueBalance >= 0) {
        // NB: positive valueBalance "gives" money to the transparent value pool just as inputs do
        nValue += valueBalance;

        if (!MoneyRange(valueBalance) || !MoneyRange(nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    for (std::vector<JSDescription>::const_iterator it(vJoinSplit.begin()); it != vJoinSplit.end(); ++it)
    {
        // NB: vpub_new "gives" money to the transparent value pool just as inputs do
        nValue += it->vpub_new;

        if (!MoneyRange(it->vpub_new) || !MoneyRange(nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    return nValue;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    if (!fOverwintered) {
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
    } else if (nVersion >= SAPLING_MIN_TX_VERSION) {
        str += strprintf("CTransaction(hash=%s, ver=%d, fOverwintered=%d, nVersionGroupId=%08x, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u, valueBalance=%u, vShieldedSpend.size=%u, vShieldedOutput.size=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            fOverwintered,
            nVersionGroupId,
            vin.size(),
            vout.size(),
            nLockTime,
            nExpiryHeight,
            valueBalance,
            vShieldedSpend.size(),
            vShieldedOutput.size());
    } else if (nVersion >= OVERWINTER_MIN_TX_VERSION) {
        str += strprintf("CTransaction(hash=%s, ver=%d, fOverwintered=%d, nVersionGroupId=%08x, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            fOverwintered,
            nVersionGroupId,
            vin.size(),
            vout.size(),
            nLockTime,
            nExpiryHeight);
    }
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}

// Set default values of new CMutableTransaction based on consensus rules at given height.
CMutableTransaction CreateNewContextualCMutableTransaction(const Consensus::Params& consensusParams, int nHeight)
{
    CMutableTransaction mtx;
    bool isOverwintered = consensusParams.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_OVERWINTER);
    if (isOverwintered) {
        mtx.fOverwintered = true;
        mtx.nExpiryHeight = 0;
        if (consensusParams.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_SAPLING)) {
            mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
            mtx.nVersion = SAPLING_TX_VERSION;
        } else {
            mtx.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID;
            mtx.nVersion = OVERWINTER_TX_VERSION;
        }
    }
    return mtx;
}
