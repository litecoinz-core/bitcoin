// Copyright (c) 2020 The LitecoinZ Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/inputcontrol.h>

void CInputControl::SetNull()
{
    m_fee.reset();
    nQuantity = 0;
    nAmount = 0;
    nPayFee = 0;
    nAfterFee = 0;
    m_min_depth = 0;
    m_max_depth = INT_MAX;
}
