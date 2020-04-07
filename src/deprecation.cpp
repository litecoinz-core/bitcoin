// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <deprecation.h>

#include <chainparams.h>
#include <shutdown.h>
#include <ui_interface.h>
#include <util/system.h>
#include <util/translation.h>

CDeprecation::CDeprecation(const int approxreleaseheight) : approxreleaseheight_(approxreleaseheight)
{
    nDeprecationHeight = approxreleaseheight_ + (RELEASE_TO_DEPRECATION_WEEKS * 7 * 24 * EXPECTED_BLOCKS_PER_HOUR);
}

CDeprecation::~CDeprecation() {
}

int CDeprecation::getDeprecationHeight()
{
    return nDeprecationHeight;
}

void CDeprecation::EnforceNodeDeprecation(int nHeight, bool forceLogging)
{
    int blocksToDeprecation = nDeprecationHeight - nHeight;
    if (blocksToDeprecation <= 0) {
        // In order to ensure we only log once per process when deprecation is
        // disabled (to avoid log spam), we only need to log in two cases:
        // - The deprecating block just arrived
        //   - This can be triggered more than once if a block chain reorg
        //     occurs, but that's an irregular event that won't cause spam.
        // - The node is starting
        if (blocksToDeprecation == 0 || forceLogging) {
            std::string strWarning = strprintf(_("This version has been deprecated as of block height %d. You should upgrade to the latest version of LitecoinZ.").translated, nDeprecationHeight);
            DoWarning(strWarning);
            uiInterface.ThreadSafeMessageBox(strWarning, "", CClientUIInterface::MSG_ERROR);
        }
        StartShutdown();
    } else if (blocksToDeprecation == DEPRECATION_WARN_LIMIT || (blocksToDeprecation < DEPRECATION_WARN_LIMIT && forceLogging)) {
        std::string strWarning = strprintf(_("This version will be deprecated at block height %d and will automatically shutted down. You should upgrade to the latest version of LitecoinZ.").translated, nDeprecationHeight);
        DoWarning(strWarning);
        uiInterface.ThreadSafeMessageBox(strWarning, "", CClientUIInterface::MSG_WARNING);
    }
}
