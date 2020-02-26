// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_INPUTCONTROLDIALOG_H
#define BITCOIN_QT_INPUTCONTROLDIALOG_H

#include <amount.h>
#include <univalue.h>

#include <QAbstractButton>
#include <QAction>
#include <QDialog>
#include <QList>
#include <QMenu>
#include <QPoint>
#include <QString>
#include <QTreeWidgetItem>

class PlatformStyle;
class WalletModel;

class CInputControl;

namespace Ui {
    class InputControlDialog;
}

class CInputControlWidgetItem : public QTreeWidgetItem
{
public:
    explicit CInputControlWidgetItem(QTreeWidget *parent, int type = Type) : QTreeWidgetItem(parent, type) {}
    explicit CInputControlWidgetItem(int type = Type) : QTreeWidgetItem(type) {}
    explicit CInputControlWidgetItem(QTreeWidgetItem *parent, int type = Type) : QTreeWidgetItem(parent, type) {}

    bool operator<(const QTreeWidgetItem &other) const;
};


class InputControlDialog : public QDialog
{
    Q_OBJECT

public:
    explicit InputControlDialog(const PlatformStyle *platformStyle, bool _fOnlyCoinbase, bool _fIncludeCoinbase, bool _fIncludeShielded, QWidget *parent = nullptr);
    ~InputControlDialog();

    void setModel(WalletModel *model);

    // static because also called from sendcoinsdialog
    static void updateLabels(WalletModel*, QDialog*);

    static QList<CAmount> payAmounts;
    static QString shieldFrom;

    static CInputControl *inputControl();

private:
    Ui::InputControlDialog *ui;
    WalletModel *model;
    int sortColumn;
    Qt::SortOrder sortOrder;

    QMenu *contextMenu;
    QTreeWidgetItem *contextMenuItem;
    QAction *copyTransactionHashAction;

    const PlatformStyle *platformStyle;
    bool fOnlyCoinbase;
    bool fIncludeCoinbase;
    bool fIncludeShielded;

    void sortView(int, Qt::SortOrder);
    void updateView();

    enum
    {
        COLUMN_QUANTITY,
        COLUMN_AMOUNT,
        COLUMN_LABEL,
        COLUMN_ADDRESS,
        COLUMN_DATE,
        COLUMN_CONFIRMATIONS,
    };

    enum
    {
        TxHashRole = Qt::UserRole,
        VOutRole
    };

    friend class CInputControlWidgetItem;

private Q_SLOTS:
    void showMenu(const QPoint &);
    void copyAmount();
    void copyLabel();
    void copyAddress();
    void copyTransactionHash();
    void clipboardQuantity();
    void clipboardAmount();
    void clipboardFee();
    void clipboardAfterFee();
    void viewItemSelectionChanged();
    void headerSectionClicked(int);
    void buttonBoxClicked(QAbstractButton*);
};

#endif // BITCOIN_QT_INPUTCONTROLDIALOG_H
