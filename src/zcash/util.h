// Copyright (c) 2016-2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZC_UTIL_H_
#define ZC_UTIL_H_

#include <vector>
#include <cstdint>

std::vector<unsigned char> convertIntToVectorLE(const uint64_t val_int);
std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes);
uint64_t convertVectorToInt(const std::vector<bool>& v);

#endif // ZC_UTIL_H_
