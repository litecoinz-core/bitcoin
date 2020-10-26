Notable changes
===============

Other issues
============

Changelog
=========

4481bd5 RPC sendrawtransaction returns error if tx expiring soon
25cf136 Update qa tests broken by expiring soon threshold
e66ee49 RPC createrawtransaction returns error if tx expiring soon
d1860f7 Don't propagate txs which are expiring soon in p2p messages
66c0208 Mitigate potential tx expiry height related DoS vector
3e2feac Add support for 'notfound' message to mininode
2db52f3 Adjust z_mergetoaddress assertions in Sapling rpc test
e305d4d Add additional z_mergetoaddress parameter tests
f2fdc46 Better error messages when sending between Sprout and Sapling
e2e3551 Add locking for Sapling notes
f0e9b68 Add Sapling support to z_mergetoaddress
bb0d42e Extend Sprout mergetoaddress rpc test to also work for Sapling
2943c42 Add fail method to rpc test utils
1bb8a18 Fix z_mergetoaddress parameter tests
1263ef7 Make sapling the default for z_getnewaddress RPC
