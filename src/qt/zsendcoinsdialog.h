// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ZSENDCOINSDIALOG_H
#define BITCOIN_QT_ZSENDCOINSDIALOG_H

#include <qt/walletmodel.h>

#include <QDialog>
#include <QMessageBox>
#include <QString>
#include <QTimer>

class ClientModel;
class PlatformStyle;
class ZSendCoinsEntry;
class SendCoinsRecipient;

namespace Ui {
    class ZSendCoinsDialog;
}

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending litecoinzs */
class ZSendCoinsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ZSendCoinsDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~ZSendCoinsDialog();

    void setClientModel(ClientModel *clientModel);
    void setModel(WalletModel *model);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void setAddress(const QString &address);
    void pasteEntry(const SendCoinsRecipient &rv);
    bool handlePaymentRequest(const SendCoinsRecipient &recipient);

public Q_SLOTS:
    void clear();
    void reject();
    void accept();
    ZSendCoinsEntry *addEntry();
    void updateTabsAndLabels();
    void setBalance(const interfaces::WalletBalances& balances);

Q_SIGNALS:
    void coinsSent();

private:
    Ui::ZSendCoinsDialog *ui;
    ClientModel *clientModel;
    WalletModel *model;
    bool fFeeMinimized;
    bool fNewRecipientAllowed;
    const PlatformStyle *platformStyle;

    // Process WalletModel::SendCoinsReturn and generate a pair consisting
    // of a message and message flags for use in Q_EMIT message().
    // Additional parameter msgArg can be used via .arg(msgArg).
    void processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg = QString());
    void minimizeFeeSection(bool fMinimize);
    void updateFeeMinimizedLabel();
    // Update the passed in CInputControl with state from the GUI
    void updateInputControlState(CInputControl& ctrl);

private Q_SLOTS:
    void on_sendButton_clicked();
    void on_buttonChooseFee_clicked();
    void on_buttonMinimizeFee_clicked();
    void removeZEntry(ZSendCoinsEntry* entry);
    void updateDisplayUnit();
    void inputControlButtonClicked();
    void inputControlUpdateLabels();
    void inputControlClipboardQuantity();
    void inputControlClipboardAmount();
    void inputControlClipboardFee();
    void inputControlClipboardAfterFee();
    void updateFeeSectionControls();
    void updateFeeLabel();

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);
};


#define SEND_CONFIRM_DELAY   3

class ZSendConfirmationDialog : public QMessageBox
{
    Q_OBJECT

public:
    ZSendConfirmationDialog(const QString& title, const QString& text, const QString& informative_text = "", const QString& detailed_text = "", int secDelay = SEND_CONFIRM_DELAY, QWidget* parent = nullptr);
    int exec();

private Q_SLOTS:
    void countDown();
    void updateYesButton();

private:
    QAbstractButton *yesButton;
    QTimer countDownTimer;
    int secDelay;
};

class ZSendResultDialog : public QMessageBox
{
    Q_OBJECT

public:
    ZSendResultDialog(const QString& title, const QString& text, QWidget* parent = nullptr);
    int exec();
};

#endif // BITCOIN_QT_ZSENDCOINSDIALOG_H
