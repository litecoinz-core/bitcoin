// Copyright (c) 2017-2019 The LitecoinZ developers
// Copyright (c) 2017-2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LITECOINZ_FETCHPARAMS_H
#define LITECOINZ_FETCHPARAMS_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <string>

bool VerifyParams(std::string file, std::string sha256expected);
bool FetchParams(std::string url, std::string file);

#endif // LITECOINZ_FETCHPARAMS_H
