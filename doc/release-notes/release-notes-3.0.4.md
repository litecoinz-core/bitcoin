3.0.4 Release Notes
===============

LitecoinZ Core version 3.0.4 is now available from:

https://github.com/litecoinz-core/litecoinz/releases/tag/v3.0.4

This is a new major version release, including new features, various bugfixes and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

https://github.com/litecoinz-core/litecoinz/issues

How to Upgrade
===============

No actions are required if you are running version v3.0.0 or later.

If you are running a version older than v3.0.0, shut it down. Wait until it has completely
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

Hard Fork at height 765949
-----------------------------------
Switching to the new PoW algorithm Zawy Lwma. This should reduce hash power spikes.

Difficulty reset
--------------------------
Adjusted difficulty for resuming from a long period of inactivity.

SPROUT Addresses
--------------------------
Creating new legacy SPROUT addresses is now disabled.

Fixes:
======

- Fix z_getnewaddress issue on encrypted wallet
- Fix gitian build
- Fix 'z_getnewaddress' issue
- Fix missing EXCLUSIVE_LOCKS_REQUIRED
- Fix 'QFlags is deprecated' warnings
- Fix 'buttonClicked is deprecated' warnings
- Fix 'QDateTime is deprecated' warnings
- Fix 'split is deprecated' warnings
- Fix 'pixmap is deprecated' warnings
- Fix bad-sapling-root-in-block issue

Known issues
===============

* There is an issue on Windows with not latin characters in user profile path. To solve this issue please start LitecoinZ using parameters ```-datadir``` and ```-paramsdir``` specifying a custom folder. Example: litecoinz-qt.exe -datadir=C:\LTZ\Data -paramsdir=C:\LTZ\Params
