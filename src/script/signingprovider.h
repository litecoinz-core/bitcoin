// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGNINGPROVIDER_H
#define BITCOIN_SCRIPT_SIGNINGPROVIDER_H

#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/standard.h>
#include <sync.h>

#include <zcash/Address.hpp>
#include <zcash/NoteEncryption.hpp>

struct KeyOriginInfo;

/** An interface to be implemented by keystores that support signing. */
class SigningProvider
{
public:
    virtual ~SigningProvider() {}
    virtual bool GetCScript(const CScriptID &scriptid, CScript& script) const { return false; }
    virtual bool HaveCScript(const CScriptID &scriptid) const { return false; }
    virtual bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const { return false; }
    virtual bool GetKey(const CKeyID &address, CKey& key) const { return false; }

    virtual bool HaveKey(const CKeyID &address) const { return false; }
    virtual bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const { return false; }

    //! Set the Zec HD seed for this keystore
    virtual bool SetZecHDSeed(const HDSeed& seed) { return false; }
    virtual bool HaveZecHDSeed() const { return false; }
    //! Get the Zec HD seed for this keystore
    virtual bool GetZecHDSeed(HDSeed& seedOut) const { return false; }

    //! Add a spending key to the store.
    virtual bool AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk) { return false; }

    //! Check whether a spending key corresponding to a given payment address is present in the store.
    virtual bool HaveSproutSpendingKey(const libzcash::SproutPaymentAddress &address) const { return false; }
    virtual bool GetSproutSpendingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutSpendingKey& skOut) const { return false; }

    //! Add a Sapling spending key to the store.
    virtual bool AddSaplingSpendingKey(const libzcash::SaplingExtendedSpendingKey &sk) { return false; }

    //! Check whether a Sapling spending key corresponding to a given Sapling viewing key is present in the store.
    virtual bool HaveSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) const { return false; }
    virtual bool GetSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk, libzcash::SaplingExtendedSpendingKey& skOut) const { return false; }

    //! Support for Sapling full viewing keys
    virtual bool AddSaplingFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) { return false; }
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const { return false; }
    virtual bool GetSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk, libzcash::SaplingExtendedFullViewingKey& extfvkOut) const { return false; }

    //! Sapling incoming viewing keys
    virtual bool AddSaplingIncomingViewingKey(const libzcash::SaplingIncomingViewingKey &ivk, const libzcash::SaplingPaymentAddress &addr) { return false; }
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const { return false; }
    virtual bool GetSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr, libzcash::SaplingIncomingViewingKey& ivkOut) const { return false; }
    virtual bool GetSaplingExtendedSpendingKey(const libzcash::SaplingPaymentAddress &addr, libzcash::SaplingExtendedSpendingKey &extskOut) const { return false; }

    //! Support for Sprout viewing keys
    virtual bool AddSproutViewingKey(const libzcash::SproutViewingKey &vk) { return false; }
    virtual bool RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk) { return false; }
    virtual bool HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const { return false; }
    virtual bool GetSproutViewingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutViewingKey& vkOut) const { return false; }
};

extern const SigningProvider& DUMMY_SIGNING_PROVIDER;

class HidingSigningProvider : public SigningProvider
{
private:
    const bool m_hide_secret;
    const bool m_hide_origin;
    const SigningProvider* m_provider;

public:
    HidingSigningProvider(const SigningProvider* provider, bool hide_secret, bool hide_origin) : m_hide_secret(hide_secret), m_hide_origin(hide_origin), m_provider(provider) {}
    bool GetCScript(const CScriptID& scriptid, CScript& script) const override;
    bool GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const override;
    bool GetKey(const CKeyID& keyid, CKey& key) const override;
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override;
};

struct FlatSigningProvider final : public SigningProvider
{
    std::map<CScriptID, CScript> scripts;
    std::map<CKeyID, CPubKey> pubkeys;
    std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>> origins;
    std::map<CKeyID, CKey> keys;

    bool GetCScript(const CScriptID& scriptid, CScript& script) const override;
    bool GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const override;
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override;
    bool GetKey(const CKeyID& keyid, CKey& key) const override;
};

FlatSigningProvider Merge(const FlatSigningProvider& a, const FlatSigningProvider& b);

/** Fillable signing provider that keeps keys in an address->secret map */
class FillableSigningProvider : public SigningProvider
{
protected:
    mutable CCriticalSection cs_KeyStore;

    HDSeed zecHDSeed;

    using KeyMap = std::map<CKeyID, CKey>;
    using ScriptMap = std::map<CScriptID, CScript>;

    KeyMap mapKeys GUARDED_BY(cs_KeyStore);
    ScriptMap mapScripts GUARDED_BY(cs_KeyStore);

    using SproutSpendingKeyMap = std::map<libzcash::SproutPaymentAddress, libzcash::SproutSpendingKey>;
    using SproutViewingKeyMap = std::map<libzcash::SproutPaymentAddress, libzcash::SproutViewingKey>;
    using NoteDecryptorMap = std::map<libzcash::SproutPaymentAddress, ZCNoteDecryption>;

    using SaplingSpendingKeyMap = std::map<libzcash::SaplingExtendedFullViewingKey, libzcash::SaplingExtendedSpendingKey>;
    using SaplingFullViewingKeyMap = std::map<libzcash::SaplingIncomingViewingKey, libzcash::SaplingExtendedFullViewingKey>;
    using SaplingIncomingViewingKeyMap = std::map<libzcash::SaplingPaymentAddress, libzcash::SaplingIncomingViewingKey>;

    SproutSpendingKeyMap mapSproutSpendingKeys GUARDED_BY(cs_KeyStore);
    SproutViewingKeyMap mapSproutViewingKeys GUARDED_BY(cs_KeyStore);
    NoteDecryptorMap mapNoteDecryptors GUARDED_BY(cs_KeyStore);

    SaplingSpendingKeyMap mapSaplingSpendingKeys GUARDED_BY(cs_KeyStore);
    SaplingFullViewingKeyMap mapSaplingFullViewingKeys GUARDED_BY(cs_KeyStore);
    SaplingIncomingViewingKeyMap mapSaplingIncomingViewingKeys GUARDED_BY(cs_KeyStore);

    void ImplicitlyLearnRelatedKeyScripts(const CPubKey& pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

public:
    virtual bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    virtual bool AddKey(const CKey &key) { return AddKeyPubKey(key, key.GetPubKey()); }
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const override;

    virtual bool HaveKey(const CKeyID &address) const override;
    virtual std::set<CKeyID> GetKeys() const;
    virtual bool GetKey(const CKeyID &address, CKey &keyOut) const override;
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const override;
    virtual std::set<CScriptID> GetCScripts() const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const override;

    //! Set the Zec HD seed for this keystore
    virtual bool SetZecHDSeed(const HDSeed& seed) override;
    virtual bool HaveZecHDSeed() const override;
    //! Get the Zec HD seed for this keystore
    virtual bool GetZecHDSeed(HDSeed& seedOut) const override;

    //! Add a spending key to the store.
    virtual bool AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk) override;

    //! Check whether a spending key corresponding to a given payment address is present in the store.
    virtual bool HaveSproutSpendingKey(const libzcash::SproutPaymentAddress &address) const override;
    virtual bool GetSproutSpendingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutSpendingKey& skOut) const override;
    virtual bool GetNoteDecryptor(const libzcash::SproutPaymentAddress &address, ZCNoteDecryption &decOut) const;
    virtual void GetSproutPaymentAddresses(std::set<libzcash::SproutPaymentAddress> &setAddress) const;

    //! Add a Sapling spending key to the store.
    virtual bool AddSaplingSpendingKey(const libzcash::SaplingExtendedSpendingKey &sk) override;

    //! Check whether a Sapling spending key corresponding to a given Sapling viewing key is present in the store.
    virtual bool HaveSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) const override;
    virtual bool GetSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk, libzcash::SaplingExtendedSpendingKey &skOut) const override;

    //! Support for Sapling full viewing keys
    virtual bool AddSaplingFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) override;
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const override;
    virtual bool GetSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk, libzcash::SaplingExtendedFullViewingKey& extfvkOut) const override;

    //! Sapling incoming viewing keys
    virtual bool AddSaplingIncomingViewingKey(const libzcash::SaplingIncomingViewingKey &ivk, const libzcash::SaplingPaymentAddress &addr) override;
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const override;
    virtual bool GetSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr, libzcash::SaplingIncomingViewingKey& ivkOut) const override;
    virtual bool GetSaplingExtendedSpendingKey(const libzcash::SaplingPaymentAddress &addr, libzcash::SaplingExtendedSpendingKey &extskOut) const override;
    virtual void GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress> &setAddress) const;

    //! Support for Sprout viewing keys
    virtual bool AddSproutViewingKey(const libzcash::SproutViewingKey &vk) override;
    virtual bool RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk) override;
    virtual bool HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const override;
    virtual bool GetSproutViewingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutViewingKey& vkOut) const override;
};

/** Return the CKeyID of the key involved in a script (if there is a unique one). */
CKeyID GetKeyForDestination(const SigningProvider& store, const CTxDestination& dest);

#endif // BITCOIN_SCRIPT_SIGNINGPROVIDER_H
