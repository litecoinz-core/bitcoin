3.0.1 Release Notes
===============

LitecoinZ Core version 3.0.1 is now available from:

https://github.com/litecoinz-core/litecoinz/releases/tag/v3.0.1

This is a new major version release, including new features, various bugfixes and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

https://github.com/litecoinz-core/litecoinz/issues

How to Upgrade
===============

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

Transactios never expire by height
-------------------
Expiration by height code inherited from ZCash was dropped out. Mempool expiration is managed from code inherited from Bitcoin Core.

Remove deprecation
-------------------
LitecoinZ Core node now never shutdown due deprecation height manager inherited from ZCash. This feature was dropped out from LitecoinZ Core source code.

Known issues
===============

* There is an issue on Windows with not latin characters in user profile path. To solve this issue please start LitecoinZ using parameters ```-datadir``` and ```-paramsdir``` specifying a custom folder. Example: litecoinz-qt.exe -datadir=C:\LTZ\Data -paramsdir=C:\LTZ\Params
