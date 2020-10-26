Notable changes
===============

Sapling network upgrade
-----------------------

The consensus code preparations for the Sapling network upgrade, as described 
in [ZIP 243](https://github.com/zcash/zips/blob/master/zip-0243.rst) and the 
[Sapling spec](https://github.com/zcash/zips/blob/master/protocol/sapling.pdf) 
are finished and  included in this release.

The activation height for the Sapling network upgrade on mainnet and testnet is 
included in this release.

Sapling will activate on mainnet at height 190000, which is expected to be mined 
on the 3rd of December 2018. Sapling will activate on testnet at height 4000.

Users running previous node version must upgrade to v2.0.0 in order to send or 
receive Sapling shielded transactions.

Sapling transaction format
--------------------------

Once Sapling has activated, transactions must use the new v4 format (including 
coinbase transactions). All RPC methods that create new transactions (such as 
`createrawtransaction` and `getblocktemplate`) will create v4 transactions once 
the Sapling activation height has been reached.

Overwinter network upgrade
--------------------------

The code preparations for the Overwinter network upgrade, as described in [ZIP 
200](https://github.com/zcash/zips/blob/master/zip-0200.rst), [ZIP
201](https://github.com/zcash/zips/blob/master/zip-0201.rst), [ZIP 
202](https://github.com/zcash/zips/blob/master/zip-0202.rst), [ZIP 
203](https://github.com/zcash/zips/blob/master/zip-0203.rst), and [ZIP 
143](https://github.com/zcash/zips/blob/master/zip-0143.rst) are 
finished and included in this release. Overwinter will activate on testnet at 
height 4000, and can also be activated at a specific height in regtest mode 
by setting the config option `-nuparams=5ba81b19:HEIGHT`.

The activation height for the Overwinter network upgrade on mainnet is included
in this release. Overwinter will activate on mainnet at height 190000, which is
expected to be mined on the 3rd of December 2018. Please upgrade to this release,
or any subsequent release, in order to follow the Overwinter network upgrade.

Overwinter transaction format
-----------------------------

Once Overwinter has activated, transactions must use the new v3 format
(including coinbase transactions). All RPC methods that create new transactions
(such as `createrawtransaction` and `getblocktemplate`) will create v3
transactions once the Overwinter activation height has been reached.

Overwinter transaction expiry
-----------------------------

Overwinter transactions created by `litecoinzd` will also have a default expiry
height set (the block height after which the transaction becomes invalid) of 20
blocks after the height of the next block. This can be configured with the
config option `-txexpirydelta`.

Minimum Difficulty Blocks allowed on testnet
--------------------------------------------
Sapling activated on testnet at block 4000. Users running v2.0.0 nodes should
upgrade to v2.0.0 which introduces a consensus rule change to allow minimum
difficulty blocks to be mined.

Hierarchical Deterministic Key Generation for Sapling
-----------------------------------------------------
All Sapling addresses will use hierarchical deterministic key generation
according to [ZIP 32](https://github.com/zcash/zips/blob/master/zip-0032.rst) 
(keypath m/32'/133'/k' on mainnet). Transparent and Sprout addresses will still 
use traditional key generation.

Backups of HD wallets, regardless of when they have been created, can
therefore be used to re-generate all possible Sapling private keys, even the
ones which haven't already been generated during the time of the backup.
Regular backups are still necessary, however, in order to ensure that
transparent and Sprout addresses are not lost.

`-disabledeprecation` removal
-----------------------------

This release removes the `-disabledeprecation` option, so that `litecoinzd` 
will always shut down in accordance with the defined deprecation policy 
(currently 16 weeks after release).

litecoinz-cli: arguments privacy
--------------------------------

The RPC command line client gained a new argument, `-stdin`
to read extra arguments from standard input, one per line until EOF/Ctrl-D.
For example:

    $ src/litecoinz-cli -stdin walletpassphrase
    mysecretcode
    120
    ^D (Ctrl-D)

It is recommended to use this for sensitive information such as private keys, as
command-line arguments can usually be read from the process table by any user on
the system.

Asm representations of scriptSig signatures now contain SIGHASH type decodes
----------------------------------------------------------------------------

The `asm` property of each scriptSig now contains the decoded signature hash
type for each signature that provides a valid defined hash type.

The following items contain assembly representations of scriptSig signatures
and are affected by this change:

- RPC `getrawtransaction`
- RPC `decoderawtransaction`
- REST `/rest/tx/` (JSON format)
- REST `/rest/block/` (JSON format when including extended tx details)
- `litecoinz-tx -json`

For example, the `scriptSig.asm` property of a transaction input that
previously showed an assembly representation of:

    304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001

now shows as:

    304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c5090[ALL]

Note that the output of the RPC `decodescript` did not change because it is
configured specifically to process scriptPubKey and not scriptSig scripts.

`-mempooltxinputlimit` deprecation
----------------------------------

The configuration option `-mempooltxinputlimit` was added in release 1.0.10 as a
short-term fix for the quadratic hashing problem inherited from Bitcoin. At the
time, transactions with many inputs were causing performance issues for miners.
Since then, several performance improvements have been merged from the Bitcoin
Core codebase that significantly reduce these issues.

The Overwinter network upgrade includes changes that solve the quadratic hashing
problem, and so `-mempooltxinputlimit` will no longer be needed - a transaction
with 1000 inputs will take just as long to validate as 10 transactions with 100
inputs each. Starting from this release, `-mempooltxinputlimit` will be enforced
before the Overwinter activation height is reached, but will be ignored once
Overwinter activates. The option will be removed entirely in a future release
after Overwinter has activated.

`NODE_BLOOM` service bit
------------------------

Support for the `NODE_BLOOM` service bit, as described in [BIP
111](https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki), has been
added to the P2P protocol code.

BIP 111 defines a service bit to allow peers to advertise that they support
Bloom filters (such as used by SPV clients) explicitly. It also bumps the protocol
version to allow peers to identify old nodes which allow Bloom filtering of the
connection despite lacking the new service bit.

In this version, it is only enforced for peers that send protocol versions
`>=170004`. For the next major version it is planned that this restriction will be
removed. It is recommended to update SPV clients to check for the `NODE_BLOOM`
service bit for nodes that report version 170004 or newer.

UTXO and note merging
---------------------

In order to simplify the process of combining many small UTXOs and notes into a
few larger ones, a new RPC method `z_mergetoaddress` has been added. It merges
funds from t-addresses, z-addresses, or both, and sends them to a single
t-address or z-address.

Unlike most other RPC methods, `z_mergetoaddress` operates over a particular
quantity of UTXOs and notes, instead of a particular amount of LTZ. By default,
it will merge 50 UTXOs and 10 notes at a time; these limits can be adjusted with
the parameters `transparent_limit` and `shielded_limit`.

`z_mergetoaddress` also returns the number of UTXOs and notes remaining in the
given addresses, which can be used to automate the merging process (for example,
merging until the number of UTXOs falls below some value).

UTXO memory accounting
----------------------

The default -dbcache has been changed in this release to 450MiB. Users can set
-dbcache to a higher value (e.g. to keep the UTXO set more fully cached in memory).
Users on low-memory systems (such as systems with 1GB or less) should consider specifying
a lower value for this parameter.

Additional information relating to running on low-memory systems can be found here: 
[reducing-memory-usage.md](https://github.com/litecoinz-project/litecoinz/blob/master/doc/reducing-memory-usage.md).
