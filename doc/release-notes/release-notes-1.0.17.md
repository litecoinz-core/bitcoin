Notable changes
===============

Reset difficulty
----------------

After the soft-fork we discover difficulty was inaccurate. A resert is performed during the nPowAveragingWindow.

Fix Sync issue
--------------

This release fix a sync issue on new wallet installations or on wallet where the last block synced is previous the algo fork.

Changelog
=========

* 2ebcc3e Add new nodes
* 946c00c Update version to 1.0.17
* 24fbd95 Add new nodes
* b62a21a Fix check of new diff while downloading/reindexing blocks generated before algo fork
* 3f08b63 Reset the difficulty as asked from pools and miners
