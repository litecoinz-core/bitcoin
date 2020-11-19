3.0.2 Release Notes
===============

LitecoinZ Core version 3.0.2 is now available from:

https://github.com/litecoinz-core/litecoinz/releases/tag/v3.0.2

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

LWMA difficulty adjustment algorithm
------------------------------------
The DigiShield difficulty adjustment algorithm has been replaced by LWMA. A soft fork will automatically occur at block height 600,000.

Mempool expiry time
-------------------
The mempool expiration time of unconfirmed transactions has been decreased to 72 hours

Fixes:
======

- Enable fallback fee using default value if estimate fee is not yet available
- Increase console command max length
- Set default addresses to legacy
- Fix 'Building Witnesses' percentage formatting
- Fix leak in CoinControlDialog::updateView
- Fix QFileDialog for static builds
- Workaround negative nsecs bug in boost's wait_until
- Handle duplicate fileid exception and concurrent wallet loading
- Strip any trailing in -datadir, -blocksdir and -paramsdir paths

Known issues
===============

* There is an issue on Windows with not latin characters in user profile path. To solve this issue please start LitecoinZ using parameters ```-datadir``` and ```-paramsdir``` specifying a custom folder. Example: litecoinz-qt.exe -datadir=C:\LTZ\Data -paramsdir=C:\LTZ\Params
