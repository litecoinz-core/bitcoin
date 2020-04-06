// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/keyorigin.h>
#include <script/signingprovider.h>
#include <script/standard.h>

#include <util/system.h>

const SigningProvider& DUMMY_SIGNING_PROVIDER = SigningProvider();

template<typename M, typename K, typename V>
bool LookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return true;
    }
    return false;
}

bool HidingSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    return m_provider->GetCScript(scriptid, script);
}

bool HidingSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    return m_provider->GetPubKey(keyid, pubkey);
}

bool HidingSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    if (m_hide_secret) return false;
    return m_provider->GetKey(keyid, key);
}

bool HidingSigningProvider::GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const
{
    if (m_hide_origin) return false;
    return m_provider->GetKeyOrigin(keyid, info);
}

bool FlatSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const { return LookupHelper(scripts, scriptid, script); }
bool FlatSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const { return LookupHelper(pubkeys, keyid, pubkey); }
bool FlatSigningProvider::GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const
{
    std::pair<CPubKey, KeyOriginInfo> out;
    bool ret = LookupHelper(origins, keyid, out);
    if (ret) info = std::move(out.second);
    return ret;
}
bool FlatSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const { return LookupHelper(keys, keyid, key); }

FlatSigningProvider Merge(const FlatSigningProvider& a, const FlatSigningProvider& b)
{
    FlatSigningProvider ret;
    ret.scripts = a.scripts;
    ret.scripts.insert(b.scripts.begin(), b.scripts.end());
    ret.pubkeys = a.pubkeys;
    ret.pubkeys.insert(b.pubkeys.begin(), b.pubkeys.end());
    ret.keys = a.keys;
    ret.keys.insert(b.keys.begin(), b.keys.end());
    ret.origins = a.origins;
    ret.origins.insert(b.origins.begin(), b.origins.end());
    return ret;
}

void FillableSigningProvider::ImplicitlyLearnRelatedKeyScripts(const CPubKey& pubkey)
{
    AssertLockHeld(cs_KeyStore);
    CKeyID key_id = pubkey.GetID();
    // This adds the redeemscripts necessary to detect P2WPKH and P2SH-P2WPKH
    // outputs. Technically P2WPKH outputs don't have a redeemscript to be
    // spent. However, our current IsMine logic requires the corresponding
    // P2SH-P2WPKH redeemscript to be present in the wallet in order to accept
    // payment even to P2WPKH outputs.
    // Also note that having superfluous scripts in the keystore never hurts.
    // They're only used to guide recursion in signing and IsMine logic - if
    // a script is present but we can't do anything with it, it has no effect.
    // "Implicitly" refers to fact that scripts are derived automatically from
    // existing keys, and are present in memory, even without being explicitly
    // loaded (e.g. from a file).
    if (pubkey.IsCompressed()) {
        CScript script = GetScriptForDestination(WitnessV0KeyHash(key_id));
        // This does not use AddCScript, as it may be overridden.
        CScriptID id(script);
        mapScripts[id] = std::move(script);
    }
}

bool FillableSigningProvider::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool FillableSigningProvider::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    ImplicitlyLearnRelatedKeyScripts(pubkey);
    return true;
}

bool FillableSigningProvider::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    return mapKeys.count(address) > 0;
}

std::set<CKeyID> FillableSigningProvider::GetKeys() const
{
    LOCK(cs_KeyStore);
    std::set<CKeyID> set_address;
    for (const auto& mi : mapKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

bool FillableSigningProvider::GetKey(const CKeyID &address, CKey &keyOut) const
{
    LOCK(cs_KeyStore);
    KeyMap::const_iterator mi = mapKeys.find(address);
    if (mi != mapKeys.end()) {
        keyOut = mi->second;
        return true;
    }
    return false;
}

bool FillableSigningProvider::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("FillableSigningProvider::AddCScript(): redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool FillableSigningProvider::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

std::set<CScriptID> FillableSigningProvider::GetCScripts() const
{
    LOCK(cs_KeyStore);
    std::set<CScriptID> set_script;
    for (const auto& mi : mapScripts) {
        set_script.insert(mi.first);
    }
    return set_script;
}

bool FillableSigningProvider::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

bool FillableSigningProvider::SetZecHDSeed(const HDSeed& seed)
{
    LOCK(cs_KeyStore);
    if (!zecHDSeed.IsNull()) {
        // Don't allow an existing seed to be changed. We can maybe relax this
        // restriction later once we have worked out the UX implications.
        return false;
    }
    zecHDSeed = seed;
    return true;
}

bool FillableSigningProvider::HaveZecHDSeed() const
{
    LOCK(cs_KeyStore);
    return !zecHDSeed.IsNull();
}

bool FillableSigningProvider::GetZecHDSeed(HDSeed& seedOut) const
{
    LOCK(cs_KeyStore);
    if (zecHDSeed.IsNull()) {
        return false;
    } else {
        seedOut = zecHDSeed;
        return true;
    }
}

bool FillableSigningProvider::AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk)
{
    LOCK(cs_KeyStore);
    auto address = sk.address();
    mapSproutSpendingKeys[address] = sk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(sk.receiving_key())));
    return true;
}

bool FillableSigningProvider::HaveSproutSpendingKey(const libzcash::SproutPaymentAddress &address) const
{
    LOCK(cs_KeyStore);
    return mapSproutSpendingKeys.count(address) > 0;
}

bool FillableSigningProvider::GetSproutSpendingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutSpendingKey& skOut) const
{
    {
        LOCK(cs_KeyStore);
        SproutSpendingKeyMap::const_iterator mi = mapSproutSpendingKeys.find(address);
        if (mi != mapSproutSpendingKeys.end())
        {
            skOut = mi->second;
            return true;
        }
    }
    return false;
}

bool FillableSigningProvider::GetNoteDecryptor(const libzcash::SproutPaymentAddress &address, ZCNoteDecryption &decOut) const
{
    {
        LOCK(cs_KeyStore);
        NoteDecryptorMap::const_iterator mi = mapNoteDecryptors.find(address);
        if (mi != mapNoteDecryptors.end())
        {
            decOut = mi->second;
            return true;
        }
    }
    return false;
}

void FillableSigningProvider::GetSproutPaymentAddresses(std::set<libzcash::SproutPaymentAddress> &setAddress) const
{
    setAddress.clear();
    {
        LOCK(cs_KeyStore);
        SproutSpendingKeyMap::const_iterator mi = mapSproutSpendingKeys.begin();
        while (mi != mapSproutSpendingKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
        SproutViewingKeyMap::const_iterator mvi = mapSproutViewingKeys.begin();
        while (mvi != mapSproutViewingKeys.end())
        {
            setAddress.insert((*mvi).first);
            mvi++;
        }
    }
}

bool FillableSigningProvider::AddSaplingSpendingKey(const libzcash::SaplingExtendedSpendingKey &sk)
{
    LOCK(cs_KeyStore);
    auto extfvk = sk.ToXFVK();

    // if extfvk is not in SaplingFullViewingKeyMap, add it
    if (!FillableSigningProvider::AddSaplingFullViewingKey(extfvk)) {
        return false;
    }

    mapSaplingSpendingKeys[extfvk] = sk;

    return true;
}

bool FillableSigningProvider::HaveSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) const
{
    LOCK(cs_KeyStore);
    return mapSaplingSpendingKeys.count(extfvk) > 0;
}

bool FillableSigningProvider::GetSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk, libzcash::SaplingExtendedSpendingKey &skOut) const
{
    {
        LOCK(cs_KeyStore);

        SaplingSpendingKeyMap::const_iterator mi = mapSaplingSpendingKeys.find(extfvk);
        if (mi != mapSaplingSpendingKeys.end())
        {
            skOut = mi->second;
            return true;
        }
    }
    return false;
}

bool FillableSigningProvider::AddSaplingFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk)
{
    LOCK(cs_KeyStore);
    auto ivk = extfvk.fvk.in_viewing_key();
    mapSaplingFullViewingKeys[ivk] = extfvk;

    return FillableSigningProvider::AddSaplingIncomingViewingKey(ivk, extfvk.DefaultAddress());
}

bool FillableSigningProvider::HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    LOCK(cs_KeyStore);
    return mapSaplingFullViewingKeys.count(ivk) > 0;
}

bool FillableSigningProvider::GetSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk, libzcash::SaplingExtendedFullViewingKey &extfvkOut) const
{
    LOCK(cs_KeyStore);
    SaplingFullViewingKeyMap::const_iterator mi = mapSaplingFullViewingKeys.find(ivk);
    if (mi != mapSaplingFullViewingKeys.end()) {
        extfvkOut = mi->second;
        return true;
    }
    return false;
}

bool FillableSigningProvider::AddSaplingIncomingViewingKey(const libzcash::SaplingIncomingViewingKey &ivk, const libzcash::SaplingPaymentAddress &addr)
{
    LOCK(cs_KeyStore);

    // Add addr -> SaplingIncomingViewing to SaplingIncomingViewingKeyMap
    mapSaplingIncomingViewingKeys[addr] = ivk;

    return true;
}

bool FillableSigningProvider::HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const
{
    LOCK(cs_KeyStore);
    return mapSaplingIncomingViewingKeys.count(addr) > 0;
}

bool FillableSigningProvider::GetSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr, libzcash::SaplingIncomingViewingKey& ivkOut) const
{
    LOCK(cs_KeyStore);
    SaplingIncomingViewingKeyMap::const_iterator mi = mapSaplingIncomingViewingKeys.find(addr);
    if (mi != mapSaplingIncomingViewingKeys.end()) {
        ivkOut = mi->second;
        return true;
    }
    return false;
}

bool FillableSigningProvider::GetSaplingExtendedSpendingKey(const libzcash::SaplingPaymentAddress &addr, libzcash::SaplingExtendedSpendingKey &extskOut) const
{
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingExtendedFullViewingKey extfvk;

    LOCK(cs_KeyStore);
    return GetSaplingIncomingViewingKey(addr, ivk) && GetSaplingFullViewingKey(ivk, extfvk) && GetSaplingSpendingKey(extfvk, extskOut);
}

void FillableSigningProvider::GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress> &setAddress) const
{
    setAddress.clear();
    {
        LOCK(cs_KeyStore);
        auto mi = mapSaplingIncomingViewingKeys.begin();
        while (mi != mapSaplingIncomingViewingKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
    }
}

bool FillableSigningProvider::AddSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_KeyStore);
    auto address = vk.address();
    mapSproutViewingKeys[address] = vk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(vk.sk_enc)));
    return true;
}

bool FillableSigningProvider::RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_KeyStore);
    mapSproutViewingKeys.erase(vk.address());
    return true;
}

bool FillableSigningProvider::HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const
{
    LOCK(cs_KeyStore);
    return mapSproutViewingKeys.count(address) > 0;
}

bool FillableSigningProvider::GetSproutViewingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutViewingKey& vkOut) const
{
    LOCK(cs_KeyStore);
    SproutViewingKeyMap::const_iterator mi = mapSproutViewingKeys.find(address);
    if (mi != mapSproutViewingKeys.end()) {
        vkOut = mi->second;
        return true;
    }
    return false;
}

CKeyID GetKeyForDestination(const SigningProvider& store, const CTxDestination& dest)
{
    // Only supports destinations which map to single public keys, i.e. P2PKH,
    // P2WPKH, and P2SH-P2WPKH.
    if (auto id = boost::get<PKHash>(&dest)) {
        return CKeyID(*id);
    }
    if (auto witness_id = boost::get<WitnessV0KeyHash>(&dest)) {
        return CKeyID(*witness_id);
    }
    if (auto script_hash = boost::get<ScriptHash>(&dest)) {
        CScript script;
        CScriptID script_id(*script_hash);
        CTxDestination inner_dest;
        if (store.GetCScript(script_id, script) && ExtractDestination(script, inner_dest)) {
            if (auto inner_witness_id = boost::get<WitnessV0KeyHash>(&inner_dest)) {
                return CKeyID(*inner_witness_id);
            }
        }
    }
    return CKeyID();
}
