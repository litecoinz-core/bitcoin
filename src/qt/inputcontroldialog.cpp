// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/inputcontroldialog.h>
#include <qt/forms/ui_inputcontroldialog.h>

#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <amount.h>
#include <wallet/inputcontrol.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <rpc/util.h>
#include <wallet/wallet.h>
#include <univalue.h>

#include <QApplication>
#include <QCursor>
#include <QDialogButtonBox>
#include <QFlags>
#include <QIcon>
#include <QSettings>
#include <QTreeWidget>

QList<CAmount> InputControlDialog::payAmounts;
QString InputControlDialog::shieldFrom;

static UniValue ValueFromString(const std::string &str)
{
    UniValue value;
    value.setNumStr(str);
    return value;
}

bool CInputControlWidgetItem::operator<(const QTreeWidgetItem &other) const {
    int column = treeWidget()->sortColumn();
    if (column == InputControlDialog::COLUMN_AMOUNT || column == InputControlDialog::COLUMN_DATE || column == InputControlDialog::COLUMN_CONFIRMATIONS)
        return data(column, Qt::UserRole).toLongLong() < other.data(column, Qt::UserRole).toLongLong();
    return QTreeWidgetItem::operator<(other);
}

InputControlDialog::InputControlDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InputControlDialog),
    model(nullptr),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // context menu actions
    QAction *copyAddressAction = new QAction(tr("Copy address"), this);
    QAction *copyLabelAction = new QAction(tr("Copy label"), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);
    copyTransactionHashAction = new QAction(tr("Copy transaction ID"), this);  // we need to enable/disable this

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyAmountAction);
    contextMenu->addAction(copyTransactionHashAction);

    // context menu signals
    connect(ui->treeWidget, &QWidget::customContextMenuRequested, this, &InputControlDialog::showMenu);
    connect(copyAddressAction, &QAction::triggered, this, &InputControlDialog::copyAddress);
    connect(copyLabelAction, &QAction::triggered, this, &InputControlDialog::copyLabel);
    connect(copyAmountAction, &QAction::triggered, this, &InputControlDialog::copyAmount);
    connect(copyTransactionHashAction, &QAction::triggered, this, &InputControlDialog::copyTransactionHash);

    // clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);

    connect(clipboardQuantityAction, &QAction::triggered, this, &InputControlDialog::clipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &InputControlDialog::clipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &InputControlDialog::clipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &InputControlDialog::clipboardAfterFee);

    ui->labelInputControlQuantity->addAction(clipboardQuantityAction);
    ui->labelInputControlAmount->addAction(clipboardAmountAction);
    ui->labelInputControlFee->addAction(clipboardFeeAction);
    ui->labelInputControlAfterFee->addAction(clipboardAfterFeeAction);

    // select item
    connect(ui->treeWidget, &QTreeWidget::itemSelectionChanged, this, &InputControlDialog::viewItemSelectionChanged);

    // click on header
    ui->treeWidget->header()->setSectionsClickable(true);
    connect(ui->treeWidget->header(), &QHeaderView::sectionClicked, this, &InputControlDialog::headerSectionClicked);

    // ok button
    connect(ui->buttonBox, &QDialogButtonBox::clicked, this, &InputControlDialog::buttonBoxClicked);

    ui->widgetInputControl->hide();

    ui->treeWidget->setColumnWidth(COLUMN_QUANTITY, 84);
    ui->treeWidget->setColumnWidth(COLUMN_AMOUNT, 110);
    ui->treeWidget->setColumnWidth(COLUMN_LABEL, 190);
    ui->treeWidget->setColumnWidth(COLUMN_ADDRESS, 320);
    ui->treeWidget->setColumnWidth(COLUMN_DATE, 130);
    ui->treeWidget->setColumnWidth(COLUMN_CONFIRMATIONS, 110);

    // default view is sorted by amount desc
    sortView(COLUMN_AMOUNT, Qt::DescendingOrder);

    // restore list mode and sortorder as a convenience feature
    QSettings settings;
    if (settings.contains("nInputControlSortColumn") && settings.contains("nInputControlSortOrder"))
        sortView(settings.value("nInputControlSortColumn").toInt(), (static_cast<Qt::SortOrder>(settings.value("nInputControlSortOrder").toInt())));

    GUIUtil::handleCloseWindowShortcut(this);
}

InputControlDialog::~InputControlDialog()
{
    QSettings settings;
    settings.setValue("nInputControlSortColumn", sortColumn);
    settings.setValue("nInputControlSortOrder", (int)sortOrder);

    delete ui;
}

void InputControlDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel() && _model->getAddressTableModel())
    {
        updateView();
        InputControlDialog::updateLabels(_model, this);
    }
}

// ok button
void InputControlDialog::buttonBoxClicked(QAbstractButton* button)
{
    if (ui->buttonBox->buttonRole(button) == QDialogButtonBox::AcceptRole)
        done(QDialog::Accepted); // closes the dialog
}

// context menu
void InputControlDialog::showMenu(const QPoint &point)
{
    QTreeWidgetItem *item = ui->treeWidget->itemAt(point);
    if(item)
    {
        contextMenuItem = item;

        // disable iterm Copy Transaction ID for tree roots in context menu
        if (item->data(COLUMN_ADDRESS, TxHashRole).toString().length() == 64) // transaction hash is 64 characters (this means it is a child node, so it is not a parent node in tree mode)
        {
            copyTransactionHashAction->setEnabled(true);
        }
        else // this means click on parent node in tree mode -> disable all
        {
            copyTransactionHashAction->setEnabled(false);
        }

        // show context menu
        contextMenu->exec(QCursor::pos());
    }
}

// context menu action: copy amount
void InputControlDialog::copyAmount()
{
    GUIUtil::setClipboard(BitcoinUnits::removeSpaces(contextMenuItem->text(COLUMN_AMOUNT)));
}

// context menu action: copy label
void InputControlDialog::copyLabel()
{
    if (contextMenuItem->text(COLUMN_LABEL).length() == 0 && contextMenuItem->parent())
        GUIUtil::setClipboard(contextMenuItem->parent()->text(COLUMN_LABEL));
    else
        GUIUtil::setClipboard(contextMenuItem->text(COLUMN_LABEL));
}

// context menu action: copy address
void InputControlDialog::copyAddress()
{
    if (contextMenuItem->text(COLUMN_ADDRESS).length() == 0 && contextMenuItem->parent())
        GUIUtil::setClipboard(contextMenuItem->parent()->text(COLUMN_ADDRESS));
    else
        GUIUtil::setClipboard(contextMenuItem->text(COLUMN_ADDRESS));
}

// context menu action: copy transaction id
void InputControlDialog::copyTransactionHash()
{
    GUIUtil::setClipboard(contextMenuItem->data(COLUMN_ADDRESS, TxHashRole).toString());
}

// copy label "Quantity" to clipboard
void InputControlDialog::clipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelInputControlQuantity->text());
}

// copy label "Amount" to clipboard
void InputControlDialog::clipboardAmount()
{
    GUIUtil::setClipboard(ui->labelInputControlAmount->text().left(ui->labelInputControlAmount->text().indexOf(" ")));
}

// copy label "Fee" to clipboard
void InputControlDialog::clipboardFee()
{
    GUIUtil::setClipboard(ui->labelInputControlFee->text().left(ui->labelInputControlFee->text().indexOf(" ")));
}

// copy label "After fee" to clipboard
void InputControlDialog::clipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelInputControlAfterFee->text().left(ui->labelInputControlAfterFee->text().indexOf(" ")));
}

// treeview: sort
void InputControlDialog::sortView(int column, Qt::SortOrder order)
{
    sortColumn = column;
    sortOrder = order;
    ui->treeWidget->sortItems(column, order);
    ui->treeWidget->header()->setSortIndicator(sortColumn, sortOrder);
}

// treeview: clicked on header
void InputControlDialog::headerSectionClicked(int logicalIndex)
{
    if (logicalIndex == COLUMN_QUANTITY) // click on most left column -> do nothing
    {
        ui->treeWidget->header()->setSortIndicator(sortColumn, sortOrder);
    }
    else
    {
        if (sortColumn == logicalIndex)
            sortOrder = ((sortOrder == Qt::AscendingOrder) ? Qt::DescendingOrder : Qt::AscendingOrder);
        else
        {
            sortColumn = logicalIndex;
            sortOrder = ((sortColumn == COLUMN_LABEL || sortColumn == COLUMN_ADDRESS) ? Qt::AscendingOrder : Qt::DescendingOrder); // if label or address then default => asc, else default => desc
        }

        sortView(sortColumn, sortOrder);
    }
}

// item selected by user
void InputControlDialog::viewItemSelectionChanged()
{
    if(!ui->treeWidget->selectionModel())
        return;

    if(ui->treeWidget->selectionModel()->hasSelection())
    {
        QTreeWidgetItem *item = ui->treeWidget->currentItem();

        inputControl()->UnSelect();
        ui->shieldFrom->clear();
        if (!(item->data(COLUMN_ADDRESS, TxHashRole).toString().length() == 64))
        {
            unsigned int nQuantity = item->childCount();
            std::string strAmount = item->data(COLUMN_AMOUNT, Qt::UserRole).toString().toStdString();
            CAmount nAmount = ValueFromString(strAmount).get_int64();
            CAmount nPayFee = model->wallet().getCustomFee(*inputControl());
            CAmount nAfterFee = nAmount - nPayFee;
            inputControl()->Select(nQuantity, nAmount, nPayFee, nAfterFee);
        }
        shieldFrom = item->data(COLUMN_ADDRESS, Qt::DisplayRole).toString();

        // selection changed -> update labels
        if (ui->treeWidget->isEnabled())
            InputControlDialog::updateLabels(model, this);
    }
}

void InputControlDialog::updateLabels(WalletModel *model, QDialog* dialog)
{
    if (!model)
        return;

    // nPayAmount
    CAmount nPayAmount = 0;
    for (const CAmount &amount : InputControlDialog::payAmounts)
    {
        nPayAmount += amount;
    }

    unsigned int nQuantity      = 0;
    CAmount nAmount             = 0;
    CAmount nPayFee             = 0;
    CAmount nAfterFee           = 0;
    CAmount nChange             = 0;

    inputControl()->ListSelected(nQuantity, nAmount, nPayFee, nAfterFee);

    // calculation
    if (nQuantity > 0)
    {
        // Fee
        nPayFee = model->wallet().getCustomFee(*inputControl());

        if (nPayAmount > 0)
        {
            nChange = nAmount - nPayAmount;

            // Never create dust outputs; if we would, just add the dust to the fee.
            if (nChange > 0 && nChange < MIN_CHANGE)
            {
                nPayFee += nChange;
                nChange = 0;
            }
        }

        // after fee
        nAfterFee = std::max<CAmount>(nAmount - nPayFee, 0);
    }

    // actually update labels
    int nDisplayUnit = BitcoinUnits::LTZ;
    if (model && model->getOptionsModel())
        nDisplayUnit = model->getOptionsModel()->getDisplayUnit();

    QLabel *l1 = dialog->findChild<QLabel *>("labelInputControlQuantity");
    QLabel *l2 = dialog->findChild<QLabel *>("labelInputControlAmount");
    QLabel *l3 = dialog->findChild<QLabel *>("labelInputControlFee");
    QLabel *l4 = dialog->findChild<QLabel *>("labelInputControlAfterFee");
    QLineEdit *l5 = dialog->findChild<QLineEdit *>("shieldFrom");

    // stats
    l1->setText(QString::number(nQuantity));                                 // Quantity
    l2->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, nAmount));        // Amount
    l3->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, nPayFee));        // Fee
    l4->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, nAfterFee));      // After Fee
    l5->setText(shieldFrom);                                                 // Shield From

    // Insufficient funds
    QLabel *label = dialog->findChild<QLabel *>("labelInputControlInsuffFunds");
    if (label)
        label->setVisible(nChange < 0);
}

CInputControl* InputControlDialog::inputControl()
{
    static CInputControl input_control;
    return &input_control;
}

void InputControlDialog::updateView()
{
    if (!model || !model->getOptionsModel() || !model->getAddressTableModel())
        return;

    ui->treeWidget->clear();
    ui->treeWidget->setEnabled(false); // performance, otherwise updateLabels would be called for every checked checkbox
    ui->treeWidget->setAlternatingRowColors(false);

    int nDisplayUnit = model->getOptionsModel()->getDisplayUnit();

    for (const auto& coins : model->wallet().listCoins()) {
        CInputControlWidgetItem* itemWalletAddress{nullptr};
        QString sWalletAddress = QString::fromStdString(EncodeDestination(coins.first));
        QString sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");

        // wallet address
        itemWalletAddress = new CInputControlWidgetItem(ui->treeWidget);

        itemWalletAddress->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

        // label
        itemWalletAddress->setText(COLUMN_LABEL, sWalletLabel);

        // address
        itemWalletAddress->setText(COLUMN_ADDRESS, sWalletAddress);

        CAmount nSum = 0;
        int nChildren = 0;
        for (const auto& outpair : coins.second) {
            const COutPoint& output = std::get<0>(outpair);
            const interfaces::WalletTxOut& out = std::get<1>(outpair);
            nSum += out.txout.nValue;
            nChildren++;

            CInputControlWidgetItem *itemOutput;
            itemOutput = new CInputControlWidgetItem(itemWalletAddress);
            itemOutput->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

            // address
            CTxDestination outputAddress;
            QString sAddress = "";
            if(ExtractDestination(out.txout.scriptPubKey, outputAddress))
            {
                sAddress = QString::fromStdString(EncodeDestination(outputAddress));
                if (!(sAddress == sWalletAddress))
                    itemOutput->setText(COLUMN_ADDRESS, sAddress);
            }

            // label
            if (!(sAddress == sWalletAddress)) // change
            {
                // tooltip from where the change comes from
                itemOutput->setToolTip(COLUMN_LABEL, tr("change from %1 (%2)").arg(sWalletLabel).arg(sWalletAddress));
                itemOutput->setText(COLUMN_LABEL, tr("(change)"));
            }

            // amount
            itemOutput->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, out.txout.nValue));
            itemOutput->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong)out.txout.nValue)); // padding so that sorting works correctly

            // date
            itemOutput->setText(COLUMN_DATE, GUIUtil::dateTimeStr(out.time));
            itemOutput->setData(COLUMN_DATE, Qt::UserRole, QVariant((qlonglong)out.time));

            // confirmations
            itemOutput->setText(COLUMN_CONFIRMATIONS, QString::number(out.depth_in_main_chain));
            itemOutput->setData(COLUMN_CONFIRMATIONS, Qt::UserRole, QVariant((qlonglong)out.depth_in_main_chain));

            // transaction hash
            itemOutput->setData(COLUMN_ADDRESS, TxHashRole, QString::fromStdString(output.hash.GetHex()));

            // vout index
            itemOutput->setData(COLUMN_ADDRESS, VOutRole, output.n);

            // disable sub-item
            itemOutput->setDisabled(true);
        }

        // amount
        itemWalletAddress->setText(COLUMN_QUANTITY, "(" + QString::number(nChildren) + ")");
        itemWalletAddress->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, nSum));
        itemWalletAddress->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong)nSum));
    }

    for (const auto& notes : model->wallet().listSproutNotes()) {
        CInputControlWidgetItem* itemWalletAddress{nullptr};
        QString sWalletAddress = QString::fromStdString(EncodePaymentAddress(notes.first));
        QString sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");

        // wallet address
        itemWalletAddress = new CInputControlWidgetItem(ui->treeWidget);

        itemWalletAddress->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

        // label
        itemWalletAddress->setText(COLUMN_LABEL, sWalletLabel);

        // address
        itemWalletAddress->setText(COLUMN_ADDRESS, sWalletAddress);

        CAmount nSum = 0;
        int nChildren = 0;
        for (const auto& outpair : notes.second) {
            const SproutOutPoint& output = std::get<0>(outpair);
            const interfaces::WalletSproutNote& out = std::get<1>(outpair);
            nSum += out.note.value();
            nChildren++;

            CInputControlWidgetItem *itemOutput;
            itemOutput = new CInputControlWidgetItem(itemWalletAddress);
            itemOutput->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

            // address
            libzcash::SproutPaymentAddress outputAddress = out.address;
            QString sAddress = QString::fromStdString(EncodePaymentAddress(outputAddress));
            if (!(sAddress == sWalletAddress))
                itemOutput->setText(COLUMN_ADDRESS, sAddress);

            // label
            if (!(sAddress == sWalletAddress)) // change
            {
                // tooltip from where the change comes from
                itemOutput->setToolTip(COLUMN_LABEL, tr("change from %1 (%2)").arg(sWalletLabel).arg(sWalletAddress));
                itemOutput->setText(COLUMN_LABEL, tr("(change)"));
            }

            // amount
            itemOutput->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, out.note.value()));
            itemOutput->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong)out.note.value())); // padding so that sorting works correctly

            // date
            itemOutput->setText(COLUMN_DATE, GUIUtil::dateTimeStr(out.time));
            itemOutput->setData(COLUMN_DATE, Qt::UserRole, QVariant((qlonglong)out.time));

            // confirmations
            itemOutput->setText(COLUMN_CONFIRMATIONS, QString::number(out.depth_in_main_chain));
            itemOutput->setData(COLUMN_CONFIRMATIONS, Qt::UserRole, QVariant((qlonglong)out.depth_in_main_chain));

            // transaction hash
            itemOutput->setData(COLUMN_ADDRESS, TxHashRole, QString::fromStdString(output.hash.GetHex()));

            // vout index
            itemOutput->setData(COLUMN_ADDRESS, VOutRole, output.n);

            // disable sub-item
            itemOutput->setDisabled(true);
        }

        // quantity
        itemWalletAddress->setText(COLUMN_QUANTITY, "(" + QString::number(nChildren) + ")");
        // amount
        itemWalletAddress->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, nSum));
        itemWalletAddress->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong)nSum));
    }

    for (const auto& notes : model->wallet().listSaplingNotes()) {
        CInputControlWidgetItem* itemWalletAddress{nullptr};
        QString sWalletAddress = QString::fromStdString(EncodePaymentAddress(notes.first));
        QString sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");

        // wallet address
        itemWalletAddress = new CInputControlWidgetItem(ui->treeWidget);

        itemWalletAddress->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

        // label
        itemWalletAddress->setText(COLUMN_LABEL, sWalletLabel);

        // address
        itemWalletAddress->setText(COLUMN_ADDRESS, sWalletAddress);

        CAmount nSum = 0;
        int nChildren = 0;
        for (const auto& outpair : notes.second) {
            const SaplingOutPoint& output = std::get<0>(outpair);
            const interfaces::WalletSaplingNote& out = std::get<1>(outpair);
            nSum += out.note.value();
            nChildren++;

            CInputControlWidgetItem *itemOutput;
            itemOutput = new CInputControlWidgetItem(itemWalletAddress);
            itemOutput->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

            // address
            libzcash::SaplingPaymentAddress outputAddress = out.address;
            QString sAddress = QString::fromStdString(EncodePaymentAddress(outputAddress));
            if (!(sAddress == sWalletAddress))
                itemOutput->setText(COLUMN_ADDRESS, sAddress);

            // label
            if (!(sAddress == sWalletAddress)) // change
            {
                // tooltip from where the change comes from
                itemOutput->setToolTip(COLUMN_LABEL, tr("change from %1 (%2)").arg(sWalletLabel).arg(sWalletAddress));
                itemOutput->setText(COLUMN_LABEL, tr("(change)"));
            }

            // amount
            itemOutput->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, out.note.value()));
            itemOutput->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong)out.note.value())); // padding so that sorting works correctly

            // date
            itemOutput->setText(COLUMN_DATE, GUIUtil::dateTimeStr(out.time));
            itemOutput->setData(COLUMN_DATE, Qt::UserRole, QVariant((qlonglong)out.time));

            // confirmations
            itemOutput->setText(COLUMN_CONFIRMATIONS, QString::number(out.depth_in_main_chain));
            itemOutput->setData(COLUMN_CONFIRMATIONS, Qt::UserRole, QVariant((qlonglong)out.depth_in_main_chain));

            // transaction hash
            itemOutput->setData(COLUMN_ADDRESS, TxHashRole, QString::fromStdString(output.hash.GetHex()));

            // vout index
            itemOutput->setData(COLUMN_ADDRESS, VOutRole, output.n);

            // disable sub-item
            itemOutput->setDisabled(true);
        }

        // quantity
        itemWalletAddress->setText(COLUMN_QUANTITY, "(" + QString::number(nChildren) + ")");
        // amount
        itemWalletAddress->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, nSum));
        itemWalletAddress->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong)nSum));
    }

    // sort view
    sortView(sortColumn, sortOrder);
    ui->treeWidget->setEnabled(true);
}
