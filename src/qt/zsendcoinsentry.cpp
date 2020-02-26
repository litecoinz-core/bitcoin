// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/zsendcoinsentry.h>
#include <qt/forms/ui_zsendcoinsentry.h>

#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QApplication>
#include <QClipboard>
#include <QPushButton>

ZSendCoinsEntry::ZSendCoinsEntry(const PlatformStyle *_platformStyle, QWidget *parent) :
    QStackedWidget(parent),
    ui(new Ui::ZSendCoinsEntry),
    model(nullptr),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    setCurrentWidget(ui->ZSendCoins);

    if (platformStyle->getUseExtraSpacing())
        ui->payToLayout->setSpacing(4);

    // normal bitcoin address field
    GUIUtil::setupAddressWidget(ui->payTo, this);

    // Connect signals
    connect(ui->payAmount, &BitcoinAmountField::valueChanged, this, &ZSendCoinsEntry::payAmountChanged);
    connect(ui->deleteButton, &QPushButton::clicked, this, &ZSendCoinsEntry::deleteClicked);
}

ZSendCoinsEntry::~ZSendCoinsEntry()
{
    delete ui;
}

void ZSendCoinsEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void ZSendCoinsEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, AddressBookPage::Transparent, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payTo->setText(dlg.getReturnValue());
        ui->payAmount->setFocus();
    }
}

void ZSendCoinsEntry::on_payTo_textChanged(const QString &address)
{
    updateLabel(address);
}

void ZSendCoinsEntry::setModel(WalletModel *_model)
{
    this->model = _model;

    if (_model && _model->getOptionsModel())
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ZSendCoinsEntry::updateDisplayUnit);

    clear();
}

void ZSendCoinsEntry::clear()
{
    // clear UI elements for normal payment
    ui->payTo->clear();
    ui->addAsLabel->clear();
    ui->payAmount->clear();

    // update the display unit, to not use the default ("LTZ")
    updateDisplayUnit();
}

void ZSendCoinsEntry::deleteClicked()
{
    Q_EMIT removeZEntry(this);
}

bool ZSendCoinsEntry::validate(interfaces::Node& node)
{
    if (!model)
        return false;

    // Check input validity
    bool retval = true;

    if ((!model->validateAddress(ui->payTo->text())) && (!model->validatePaymentAddress(ui->payTo->text())))
    {
        ui->payTo->setValid(false);
        retval = false;
    }

    if (!ui->payAmount->validate())
    {
        retval = false;
    }

    // Sending a zero amount is invalid
    if (ui->payAmount->value(nullptr) <= 0)
    {
        ui->payAmount->setValid(false);
        retval = false;
    }

    // Reject dust outputs:
    if (retval && GUIUtil::isDust(node, ui->payTo->text(), ui->payAmount->value())) {
        ui->payAmount->setValid(false);
        retval = false;
    }

    return retval;
}

SendCoinsRecipient ZSendCoinsEntry::getValue()
{
    recipient.address = ui->payTo->text();
    recipient.label = ui->addAsLabel->text();
    recipient.amount = ui->payAmount->value();
    recipient.fSubtractFeeFromAmount = false;

    return recipient;
}

QWidget *ZSendCoinsEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addAsLabel);
    QWidget *w = ui->payAmount->setupTabChain(ui->addAsLabel);
    QWidget::setTabOrder(w, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    return ui->deleteButton;
}

void ZSendCoinsEntry::setValue(const SendCoinsRecipient &value)
{
    recipient = value;
    {
        ui->addAsLabel->clear();
        ui->payTo->setText(recipient.address); // this may set a label from addressbook
        if (!recipient.label.isEmpty()) // if a label had been set from the addressbook, don't overwrite with an empty label
            ui->addAsLabel->setText(recipient.label);
        ui->payAmount->setValue(recipient.amount);
    }
}

void ZSendCoinsEntry::setAddress(const QString &address)
{
    ui->payTo->setText(address);
    ui->payAmount->setFocus();
}

void ZSendCoinsEntry::setAmount(const CAmount &amount)
{
    ui->payAmount->setValue(amount);
}

bool ZSendCoinsEntry::isClear()
{
    return ui->payTo->text().isEmpty();
}

void ZSendCoinsEntry::setFocus()
{
    ui->payTo->setFocus();
}

void ZSendCoinsEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Update payAmount with the current unit
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

bool ZSendCoinsEntry::updateLabel(const QString &address)
{
    if(!model)
        return false;

    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    if(!associatedLabel.isEmpty())
    {
        ui->addAsLabel->setText(associatedLabel);
        return true;
    }

    return false;
}
