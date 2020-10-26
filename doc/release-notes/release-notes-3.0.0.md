3.0.0 Release Notes
===============

LitecoinZ Core version 3.0.0 is now available from:

https://github.com/litecoinz-core/litecoinz/releases/tag/v3.0.0

This is a new major version release, including new features, various bugfixes and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

https://github.com/litecoinz-core/litecoinz/issues

How to Upgrade
===============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then make a 
backup of the file wallet.dat and run the installer (on Windows) or just copy 
over /Applications/LitecoinZ-Qt (on Mac) or litecoinz/litecoinz-qt (on Linux).

Run the following command:

```./litecoinzd -upgradewallet -rescan -reindex```

or

```./litecoinz-qt -upgradewallet -rescan -reindex```

If running on Windows:

```litecoinzd.exe -upgradewallet -rescan -reindex```

or

```litecoinz-qt.exe -upgradewallet -rescan -reindex```

Notable changes
===============

New code and look&feel
-------------------
LitecoinZ has been completely rewritten from scratch starting from a fork of Bitcoin 0.19.1 in which all the features present in previous versions of LitecoinZ have been added.

Coinbase Shielding
-------------------
Staring from v3.0.0 shielding coinbase for payments is now optional. Payments could be done directly using transparent addresses. This will relax and use less compute resource on mining pools.

New soft-fork scheduled
-----------------------------
* CSV: scheduled at block 585000
* Segwit: scheduled at block 590000
* ZawyLWMA: scheduled at block 600000

No actios are required from users and mining pool operators.

Notable changes and new features inherited from Bitcoin Core
===============

Since LitecoinZ starting from version 3.0.0 has been completely rewritten from scratch starting from a fork of Bitcoin 0.19.1 in which all the features present in previous versions of LitecoinZ have been added, this new version includes all the following new features:

From Bitcoin Core version 0.12.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.12.0.md>

From Bitcoin Core version 0.12.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.12.1.md>

From Bitcoin Core version 0.13.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.13.0.md>

From Bitcoin Core version 0.13.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.13.1.md>

From Bitcoin Core version 0.13.2
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.13.2.md>

From Bitcoin Core version 0.14.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.14.0.md>

From Bitcoin Core version 0.14.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.14.1.md>

From Bitcoin Core version 0.14.2
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.14.2.md>

From Bitcoin Core version 0.14.3
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.14.3.md>

From Bitcoin Core version 0.15.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.15.0.md>

From Bitcoin Core version 0.15.0.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.15.0.1.md>

From Bitcoin Core version 0.15.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.15.1.md>

From Bitcoin Core version 0.15.2
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.15.2.md>

From Bitcoin Core version 0.16.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.16.0.md>

From Bitcoin Core version 0.16.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.16.1.md>

From Bitcoin Core version 0.16.2
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.16.2.md>

From Bitcoin Core version 0.16.3
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.16.3.md>

From Bitcoin Core version 0.17.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.17.0.md>

From Bitcoin Core version 0.17.0.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.17.0.1.md>

From Bitcoin Core version 0.17.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.17.1.md>

From Bitcoin Core version 0.18.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.18.0.md>

From Bitcoin Core version 0.18.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.18.1.md>

From Bitcoin Core version 0.19.0
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.19.0.md>

From Bitcoin Core version 0.19.0.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.19.0.1.md>

From Bitcoin Core version 0.19.1
-----------------------------
<https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.19.1.md>

Known issues
===============

* The LitecoinZ splash screen show a wrong disk space requirement (284 GB). Do not worry about it, only 4 GB are required for downloading and storing the LitecoinZ blockchain.

* There is an issue on Windows with not latin characters in user profile path. To solve this issue please start LitecoinZ using parameters ```-datadir``` and ```-paramsdir``` specifying a custom folder. Example: litecoinz-qt.exe -datadir=C:\LTZ\Data -paramsdir=C:\LTZ\Params
