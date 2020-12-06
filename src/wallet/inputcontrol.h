// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_INPUTCONTROL_H
#define BITCOIN_WALLET_INPUTCONTROL_H

#include <amount.h>

#include <climits>

#include <optional.h>

/** Coin Control Features. */
class CInputControl
{
public:
    //! Override the wallet's m_pay_tx_fee if set
    Optional<CAmount> m_fee;
    //! Minimum chain depth value for coin availability
    int m_min_depth = 0;
    //! Maximum chain depth value for coin availability
    int m_max_depth = INT_MAX;

    CInputControl()
    {
        SetNull();
    }

    void SetNull();

    bool HasSelected() const
    {
        return (nQuantity > 0);
    }

    void Select(unsigned int quantity, CAmount amount, CAmount payFee, CAmount afterFee)
    {
       nQuantity = quantity;
       nAmount = amount;
       nPayFee = payFee;
       nAfterFee = afterFee;
    }

    void UnSelect()
    {
        nQuantity = 0;
        nAmount = 0;
        nPayFee = 0;
        nAfterFee = 0;
        m_min_depth = 0;
        m_max_depth = INT_MAX;
    }

    void ListSelected(unsigned int &quantity, CAmount &amount, CAmount &payFee, CAmount &afterFee) const
    {
        quantity = nQuantity;
        amount = nAmount;
        payFee = nPayFee;
        afterFee = nAfterFee;
    }

    CAmount GetInputBalance() const
    {
        return nAmount;
    }

private:
    unsigned int nQuantity;
    CAmount nAmount;
    CAmount nPayFee;
    CAmount nAfterFee;
};

#endif // BITCOIN_WALLET_INPUTCONTROL_H
