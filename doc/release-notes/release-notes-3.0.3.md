3.0.3 Release Notes
===============

LitecoinZ Core version 3.0.3 is now available from:

https://github.com/litecoinz-core/litecoinz/releases/tag/v3.0.3

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

Drop shielding coinbase enforcement
-----------------------------------
Since the coinbase shielding enforcement has been removed, the "shield coinbase" page
and the z_shieldcoinbase operation have been removed as they are no longer needed.

Improving asyncOp_sendmany
--------------------------
Removed several unnecessary loops on the entire utxo set, restructuring and cleaning the flow.

Fixes:
======

- Fix wallet crash on 'inputcontroldialog'
- Fix wallet crash on 'z_sendmany' when the decryption key is needed
- Fix 'SAPLING_EXTENDED_FVK'
- Fix MAX_FUTURE_BLOCK_TIME and DEFAULT_MAX_TIME_ADJUSTMENT

Known issues
===============

* There is an issue on Windows with not latin characters in user profile path. To solve this issue please start LitecoinZ using parameters ```-datadir``` and ```-paramsdir``` specifying a custom folder. Example: litecoinz-qt.exe -datadir=C:\LTZ\Data -paramsdir=C:\LTZ\Params
