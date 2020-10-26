Notable changes
===============

Native QT Wallet
----------------

A native QT Wallet was developed starting from the source code of bitcoin. This 
replace the deprecated Java GUI.

Auto download of parameter files
--------------------------------

Parameter files 'sprout-verifying.key' and 'sprout-proving.key' are now download 
at startup if needed. This means that you no longer need to run the 'fetch-params.sh'
command before running LitecoinZ.

Configuration file requirement
------------------------------

Now it's possible to run LitecoinZ without having created the configuration file
'litecoinz.conf'. Default values are used at startup and cookie based authentication
is used for RPC calls.

Transaction Fees
----------------

Actual async operation fee are reduced to 0.00001 LTZ.

Changelog
=========

* 6cd99d3 Fix resultsdialog.cpp
* 9d2f9e5 Update default startup parameter 'server=1'
* ba2e77d Fix some compilation issues
* dd22ef5 Add new nodes
* a558f84 Extend CWallet::GetFilteredNotes to enable filtering on a set
* e042453 Auto download of 'sprout-proving.key' and 'sprout-verifying.key' files at startup (if needed)
* cb76360 Native QT Wallet
* 553d2f8 Upgrade proton to 0.20.0
* d283489 Upgrade ccache to 3.3.6
* 7946c44 Upgrade Sodium to 1.0.16
* 72dbc66 Upgrade boost to 1.66.0
* 3f5c1de Update checkpoints
* 6a3eb84 Fix some comments
* ee88cfb Change output of 'z_sendmany' to json format
* 17cedeb Remove PrivacyInfo
* c351951 Allow to run even if 'litecoinz.conf' is missing
* afe11a7 Reduce async operation fee amount
* 2735af6 Use JoinSplitTestingSetup for Boost sighash tests
* 5bd9c72 Make indentation in ActivateBestChainStep readable
* 5d7b573 Use block hash comparison for consistency check when loading block index
* 3828a88 Report non-mandatory script failures correctly
* 4f3f95b Fix syntax examples for z_importwallet and export
* 8ed984d Check Equihash solution when loading block index
* d6cde67 Merge pull request #8 from leto/hashreserved
* f484100 Read hashReserved from disk instead of assuming 0, to avoid sync issues
* 9a0f3f2 Add fs.cpp/h
* 0a8082e Add z_listunshielded RPC call
* d826984 Add some const declarations where they are appropriate
* 16ec8fa Add z_listunspent RPC call
* 4232f1f zkey_import_export: Synchronize mempools before mining
* f7de112 Build improvements
* 5811b71 Set copyright holders displayed in notices separately
* 9b53e5b Add listCommands() to CRPCTable
* cb9fed3 [RPC] remove the option of having multiple timer
* cb0d952 Fix SelectBaseParamsFromCommandLine in 'src/zcbenchmarks.cpp'
* cdaba59 limit total length of user agent comments
* a2edb56 Initialize logging before we do parameter interaction
* 95c4bc9 Bircoin Core Backports
* f59ea0b Refactor parameter interaction, call it before AppInit2()
* 08e30d4 Remove old .travis.yml
* 9ba4d0e Improve sync performance by increasing default value of dbcache
* 011bcc8 Check chainValueZat when checking value pool monitoring
* b2cc6a7 Enable Bash completion for -exportdir
* 3603afc Relay blocks when pruning
* cd91c7d uint256::GetCheapHash bigendian compatibility
* e12e5a0 Assert now > 0 in GetTime GetTimeMillis GetTimeMicros
* 8563004 Reduce block timeout to 10 minutes
* 36cfa1b Track block download times per individual block
* 329a443 init: allow shutdown during 'Activating best chain...'
* 040d4f5 Bugfix: gitian: Add curl to packages (now needed for depends)
* 8f3be79 Fix calculation of balances and available coins
* 9515ee5 Take the training wheels off anti-fee-sniping (Peter Todd)
* d99f8fa Add InMempool()
* 384d087 [doc/log] Fix markdown syntax
* a560e40 [0.12] Mark p2p alert system as deprecated
* ac994b2 net: Create CConnman to encapsulate p2p connections
* 26b20d8 net: move CBanDB and CAddrDB out of net.h/cpp
* 7264a25 Store banlist.dat on disk
