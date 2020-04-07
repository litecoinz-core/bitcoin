// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SHIELDCOINBASEDIALOG_H
#define BITCOIN_QT_SHIELDCOINBASEDIALOG_H

#include <qt/walletmodel.h>

#include <QDialog>
#include <QMessageBox>
#include <QString>
#include <QTimer>

class AddressTableModel;
class WalletModel;
class ClientModel;
class PlatformStyle;

namespace Ui {
    class ShieldCoinbaseDialog;
}

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for shielding litecoinzs */
class ShieldCoinbaseDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ShieldCoinbaseDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~ShieldCoinbaseDialog();

    void setClientModel(ClientModel *clientModel);
    void setModel(WalletModel *model);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

public Q_SLOTS:
    void clear();
    void reject();
    void accept();
    void updateTabsAndLabels();
    void setBalance(const interfaces::WalletBalances& balances);

Q_SIGNALS:
    void coinsSent();

private:
    Ui::ShieldCoinbaseDialog *ui;
    ClientModel *clientModel;
    WalletModel *model;
    bool fFeeMinimized;
    const PlatformStyle *platformStyle;

    bool updateLabel(const QString &address);

    void minimizeFeeSection(bool fMinimize);
    void updateFeeMinimizedLabel();
    // Update the passed in CInputControl with state from the GUI
    void updateInputControlState(CInputControl& ctrl);

private Q_SLOTS:
    void on_shieldButton_clicked();
    void on_buttonChooseFee_clicked();
    void on_buttonMinimizeFee_clicked();
    void on_addressBookButton_clicked();
    void deleteClicked();
    void updateDisplayUnit();
    void inputControlButtonClicked();
    void on_shieldTo_textChanged(const QString &address);
    void useMaxUtxosChecked(int);
    void inputControlUpdateLabels();
    void inputControlClipboardQuantity();
    void inputControlClipboardAmount();
    void inputControlClipboardFee();
    void inputControlClipboardAfterFee();
    void updateFeeSectionControls();
    void updateFeeLabel();
    void updateShieldLimitLabel();

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);
};


#define SEND_CONFIRM_DELAY   3

class ShieldConfirmationDialog : public QMessageBox
{
    Q_OBJECT

public:
    ShieldConfirmationDialog(const QString& title, const QString& text, const QString& informative_text = "", const QString& detailed_text = "", int secDelay = SEND_CONFIRM_DELAY, QWidget* parent = nullptr);
    int exec();

private Q_SLOTS:
    void countDown();
    void updateYesButton();

private:
    QAbstractButton *yesButton;
    QTimer countDownTimer;
    int secDelay;
};

class ShieldResultDialog : public QMessageBox
{
    Q_OBJECT

public:
    ShieldResultDialog(const QString& title, const QString& text, QWidget* parent = nullptr);
    int exec();
};

#endif // BITCOIN_QT_SHIELDCOINBASEDIALOG_H
