// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_DEPRECATION_H
#define ZCASH_DEPRECATION_H

#include <validation.h>

// Deprecation policy:
// Shut down nodes running this version of code, 16 weeks' worth of blocks after the estimated
// release block height. A warning is shown during the 14 days' worth of blocks prior to shut down.
static const int RELEASE_TO_DEPRECATION_WEEKS = 16;

// Expected number of blocks per hour
static const int EXPECTED_BLOCKS_PER_HOUR = 48;

// Number of blocks before deprecation to warn users
static const int DEPRECATION_WARN_LIMIT = 14 * 24 * EXPECTED_BLOCKS_PER_HOUR;

class CDeprecation
{
protected:
    int nDeprecationHeight;

public:
    CDeprecation(const int approxreleaseheight);
    ~CDeprecation();

    /** Return deprecation height */
    int getDeprecationHeight();

    /**
     * Checks whether the node is deprecated based on the current block height, and
     * shuts down the node with an error if so (and deprecation is not disabled for
     * the current client version). Warning and error messages are sent to the debug
     * log, the metrics UI, and (if configured) -alertnofity.
     *
     * fThread means run -alertnotify in a free-running thread.
     */
    void EnforceNodeDeprecation(int nHeight, bool forceLogging = false);

private:
    int approxreleaseheight_;
};

#endif // ZCASH_DEPRECATION_H
