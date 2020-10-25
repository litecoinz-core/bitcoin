// Copyright (c) 2017-2020 The LitecoinZ developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef WIN32
#define CURL_STATICLIB
#endif

#include <fs.h>
#include <fetchparams.h>
#include <ui_interface.h>
#include <util/system.h>
#include <util/translation.h>

#include <sstream>
#include <stdio.h>
#include <string>

#include <curl/curl.h>
#include <openssl/sha.h>

#include <boost/thread.hpp>

std::string filename;
int reportDone;

bool VerifyParams(const fs::path& path, std::string sha256expected)
{
    FILE *file = fsbridge::fopen(path, "rb");
    filename = path.filename().string();

    reportDone = 0;
    int bytesRead = 0;
    int totalBytes = fs::file_size(path);
    int soFar = 0;

    if (file) {
        LogPrintf("Verifying %s...\n", path.string());
        LogPrintf("[0%%]..."); /* Continued */

        unsigned char buffer[BUFSIZ];
        unsigned char hash[SHA256_DIGEST_LENGTH];

        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        while((bytesRead = fread(buffer, 1, BUFSIZ, file)))
        {
            boost::this_thread::interruption_point();
            SHA256_Update(&ctx, buffer, bytesRead);
            soFar = soFar + (int)bytesRead;
            const int percentageDone = std::max(1, std::min(99, (int)((double)soFar / (double)totalBytes * 100)));
            if (reportDone < percentageDone/10) {
                // report every 10% step
                LogPrintf("[%d%%]...", percentageDone); /* Continued */
                reportDone = percentageDone/10;
            }
            uiInterface.ShowProgress(_((strprintf("Verifying %s", filename)).c_str()).translated, percentageDone, false);
        }
        SHA256_Final(hash, &ctx);
        LogPrintf("[DONE].\n");

        fclose(file);

        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            oss << strprintf("%02x", hash[i]);

        if (!(sha256expected.compare(oss.str()) == 0)) {
            fs::remove(path);
            return error("VerifyParams(): sha256 checksum mismatch %s", oss.str());
        }
    } else {
        LogPrintf("Warning: Could not open file %s\n", path.string());
        return false;
    }

    return true;
}

static int xferinfo(void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
    boost::this_thread::interruption_point();
    if ((double)dlnow > 0) {
        const int percentageDone = std::max(1, std::min(99, (int)((double)dlnow / (double)dltotal * 100)));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone); /* Continued */
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_((strprintf("Downloading %s", filename)).c_str()).translated, percentageDone, false);
    }
    return 0;
}

bool FetchParams(std::string url, const fs::path& path)
{
    CURL *curl;
    FILE *file = fsbridge::fopen(path, "wb");
    filename = path.filename().string();

    reportDone = 0;

    if ((curl = curl_easy_init())) {
        LogPrintf("Downloading %s...\n", url);
        LogPrintf("[0%%]..."); /* Continued */

        if (file) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);

            CURLcode ret = curl_easy_perform(curl);
            fclose(file);

            if (ret != CURLE_OK) {
                return error("FetchParams(): %s", curl_easy_strerror(ret));
            }
        } else {
            LogPrintf("Warning: Could not write to file %s\n", path.string());
            return false;
        }
        curl_easy_cleanup(curl);
        LogPrintf("[DONE].\n");
    }

    return true;
}
