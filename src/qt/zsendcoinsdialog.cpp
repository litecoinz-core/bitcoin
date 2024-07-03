// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/zsendcoinsdialog.h>
#include <qt/forms/ui_zsendcoinsdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/inputcontroldialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/sendcoinsdialog.h>
#include <qt/zsendcoinsentry.h>

#include <chainparams.h>
#include <core_io.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <wallet/inputcontrol.h>
#include <ui_interface.h>
#include <txmempool.h>
#include <policy/fees.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>

#include <array>

#include <QFontMetrics>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>

ZSendCoinsDialog::ZSendCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ZSendCoinsDialog),
    clientModel(nullptr),
    model(nullptr),
    fFeeMinimized(true),
    fNewRecipientAllowed(true),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->addButton->setIcon(QIcon());
        ui->clearButton->setIcon(QIcon());
        ui->sendButton->setIcon(QIcon());
    } else {
        ui->addButton->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->sendButton->setIcon(_platformStyle->SingleColorIcon(":/icons/send"));
    }

    addEntry();

    connect(ui->addButton, &QPushButton::clicked, this, &ZSendCoinsDialog::addEntry);
    connect(ui->clearButton, &QPushButton::clicked, this, &ZSendCoinsDialog::clear);

    // Input Control
    connect(ui->pushButtonInputControl, &QPushButton::clicked, this, &ZSendCoinsDialog::inputControlButtonClicked);

    // Input Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &ZSendCoinsDialog::inputControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &ZSendCoinsDialog::inputControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &ZSendCoinsDialog::inputControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &ZSendCoinsDialog::inputControlClipboardAfterFee);
    ui->labelInputControlQuantity->addAction(clipboardQuantityAction);
    ui->labelInputControlAmount->addAction(clipboardAmountAction);
    ui->labelInputControlFee->addAction(clipboardFeeAction);
    ui->labelInputControlAfterFee->addAction(clipboardAfterFeeAction);

    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nZTransactionFee"))
        settings.setValue("nZTransactionFee", (qint64)10000);
    ui->customFee->SetAllowEmpty(false);
    ui->customFee->setValue(settings.value("nZTransactionFee").toLongLong());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());
}

void ZSendCoinsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
}

void ZSendCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            ZSendCoinsEntry *entry = qobject_cast<ZSendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                entry->setModel(_model);
            }
        }

        interfaces::WalletBalances balances = _model->wallet().getBalances();
        setBalance(balances);
        connect(_model, &WalletModel::balanceChanged, this, &ZSendCoinsDialog::setBalance);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ZSendCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        // Input Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ZSendCoinsDialog::inputControlUpdateLabels);
        inputControlUpdateLabels();

        // fee section
        connect(ui->checkBoxCustomFee, &QCheckBox::stateChanged, this, &ZSendCoinsDialog::updateFeeSectionControls);
        connect(ui->checkBoxCustomFee, &QCheckBox::stateChanged, this, &ZSendCoinsDialog::inputControlUpdateLabels);
        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &ZSendCoinsDialog::inputControlUpdateLabels);
        CAmount requiredFee = model->wallet().getRequiredFee(1000);
        ui->customFee->SetMinValue(requiredFee);
        if (ui->customFee->value() < requiredFee) {
            ui->customFee->setValue(requiredFee);
        }
        ui->customFee->setSingleStep(requiredFee);
        updateFeeSectionControls();
        updateFeeLabel();
    }
}

ZSendCoinsDialog::~ZSendCoinsDialog()
{
    QSettings settings;
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nZTransactionFee", (qint64)ui->customFee->value());

    delete ui;
}

void ZSendCoinsDialog::on_sendButton_clicked()
{
    if(!model || !model->getOptionsModel())
        return;

    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        ZSendCoinsEntry *entry = qobject_cast<ZSendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            if(entry->validate(model->node()))
            {
                recipients.append(entry->getValue());
            }
            else if (valid)
            {
                ui->scrollArea->ensureWidgetVisible(entry);
                valid = false;
            }
        }
    }

    QString addressFrom = ui->shieldFrom->text();
    if (addressFrom.isEmpty())
    {
        valid = false;
        ui->shieldFrom->setValid(false);
    }

    if(!valid || recipients.isEmpty())
    {
        return;
    }

    fNewRecipientAllowed = false;
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return;
    }

    // prepare transaction for getting txFee earlier
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;

    // Always use a CInputControl instance
    CInputControl ctrl = *InputControlDialog::inputControl();
    updateInputControlState(ctrl);

    prepareStatus = model->prepareShieldedTransaction(currentTransaction, ctrl);

    // process prepareStatus and on error generate message shown to user
    processSendCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), currentTransaction.getTransactionFee()));

    if(prepareStatus.status != WalletModel::OK) {
        fNewRecipientAllowed = true;
        return;
    }

    CAmount txFee = currentTransaction.getTransactionFee();

    // Format confirmation message
    QStringList formatted;
    for (const SendCoinsRecipient &rcp : currentTransaction.getRecipients())
    {
        // generate amount string with wallet name in case of multiwallet
        QString amount = BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
        if (model->isMultiwallet()) {
            amount.append(tr(" from wallet '%1'").arg(GUIUtil::HtmlEscape(model->getWalletName())));
        }

        // generate address string
        QString address = rcp.address;

        QString recipientElement;

        {
            if(rcp.label.length() > 0) // label with address
            {
                recipientElement.append(tr("%1 to '%2'").arg(amount, GUIUtil::HtmlEscape(rcp.label)));
                recipientElement.append(QString(" (%1)").arg(address));
            }
            else // just address
            {
                recipientElement.append(tr("%1 to %2").arg(amount, address));
            }
        }
        formatted.append(recipientElement);
    }

    QString questionString = tr("Are you sure you want to send?");
    questionString.append("<br /><span style='font-size:10pt;'>");
    questionString.append(tr("Please, review your transaction."));
    questionString.append("</span>%1");

    if(txFee > 0)
    {
        // append fee string if a fee is required
        questionString.append("<hr /><b>");
        questionString.append(tr("Transaction fee: "));
        questionString.append("</b>");

        // append transaction fee value
        questionString.append("<span style='color:#aa0000; font-weight:bold;'>");
        questionString.append(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
        questionString.append("</span><br />");
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    CAmount totalAmount = currentTransaction.getTotalTransactionAmount() + txFee;
    QStringList alternativeUnits;
    for (const BitcoinUnits::Unit u : BitcoinUnits::availableUnits())
    {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(QString("<b>%1</b>: <b>%2</b>").arg(tr("Total Amount"))
        .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<br /><span style='font-size:10pt; font-weight:normal;'>(=%1)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + " ")));

    QString informative_text;
    QString detailed_text;
    if (formatted.size() > 1) {
        questionString = questionString.arg("");
        informative_text = tr("To review recipient list click \"Show Details...\"");
        detailed_text = formatted.join("\n\n");
    } else {
        questionString = questionString.arg("<br /><br />" + formatted.at(0));
    }

    ZSendConfirmationDialog confirmationDialog(tr("Confirm send coins"), questionString, informative_text, detailed_text, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = static_cast<QMessageBox::StandardButton>(confirmationDialog.result());

    if(retval != QMessageBox::Yes)
    {
        fNewRecipientAllowed = true;
        return;
    }

    bool sendStatus = false;

    UniValue params(UniValue::VARR);
    UniValue amounts(UniValue::VARR);

    for (const SendCoinsRecipient &rcp : currentTransaction.getRecipients())
    {
        UniValue json(UniValue::VOBJ);
        json.pushKV("address", rcp.address.toStdString());
        json.pushKV("amount", ValueFromAmount(rcp.amount));
        amounts.push_back(json);
    }

    params.push_back(addressFrom.toStdString());
    params.push_back(amounts);
    params.push_back(1);
    params.push_back(ValueFromAmount(txFee));

    QString opid;
    JSONRPCRequest request;
    request.params = params;
    request.fHelp = false;

    try
    {
        auto ret = z_sendmany(request);
        opid = QString::fromStdString(ret.get_str());

        sendStatus = true;
    }
    catch (UniValue& objError)
    {
        try // Nice formatting for standard-format error
        {
            int code = objError.find_value("code").get_int();
            std::string message = objError.find_value("message").get_str();
            QMessageBox::critical(this, "Error", QString("Error: ") + QString::fromStdString(message) + " (code " + QString::number(code) + ")");
        }
        catch (const std::runtime_error&) // raised when converting to invalid type, i.e. missing code or message
        {   // Show raw JSON object
            QMessageBox::critical(this, "Error", QString("Error: ") + QString::fromStdString(objError.write()));
        }
    }
    catch (const std::exception& e)
    {
        QMessageBox::critical(this, "Error", QString("Error: ") + QString::fromStdString(e.what()));
    }
    catch (...)
    {
        QMessageBox::critical(this, "Error", QString("Error <unknown>"));
    }

    if (sendStatus)
    {
        QString resultString = tr("Z-Send operation was submitted in background.");

        resultString.append("<table style='width:100%;'>");
        resultString.append("<br />");

        resultString.append("<tr>");
        resultString.append("<td style='width:50%; white-space:nowrap;'><b>" + tr("opid : ") + "</b></td>");
        resultString.append("<td style='width:50%; white-space:nowrap;'>" + opid + "<td>");
        resultString.append("</tr>");

        resultString.append("</table>");

        ZSendResultDialog resultDialog(tr("Z-Send operation submitted"), resultString, this);
        resultDialog.exec();

        accept();
        InputControlDialog::inputControl()->UnSelect();
        inputControlUpdateLabels();
        Q_EMIT coinsSent();
    }
    fNewRecipientAllowed = true;
}

void ZSendCoinsDialog::clear()
{
    // Clear coin control settings
    InputControlDialog::inputControl()->UnSelect();
    inputControlUpdateLabels();

    ui->shieldFrom->clear();

    // Remove entries until only one left
    while(ui->entries->count())
    {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }
    addEntry();

    updateTabsAndLabels();
}

void ZSendCoinsDialog::reject()
{
    clear();
}

void ZSendCoinsDialog::accept()
{
    clear();
}

ZSendCoinsEntry *ZSendCoinsDialog::addEntry()
{
    ZSendCoinsEntry *entry = new ZSendCoinsEntry(platformStyle, this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, &ZSendCoinsEntry::removeZEntry, this, &ZSendCoinsDialog::removeZEntry);
    connect(entry, &ZSendCoinsEntry::payAmountChanged, this, &ZSendCoinsDialog::inputControlUpdateLabels);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    updateTabsAndLabels();
    return entry;
}

void ZSendCoinsDialog::updateTabsAndLabels()
{
    setupTabChain(nullptr);
    inputControlUpdateLabels();
}

void ZSendCoinsDialog::removeZEntry(ZSendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

QWidget *ZSendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        ZSendCoinsEntry *entry = qobject_cast<ZSendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void ZSendCoinsDialog::setAddress(const QString &address)
{
    ZSendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        ZSendCoinsEntry *first = qobject_cast<ZSendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void ZSendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    ZSendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        ZSendCoinsEntry *first = qobject_cast<ZSendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    updateTabsAndLabels();
}

bool ZSendCoinsDialog::handlePaymentRequest(const SendCoinsRecipient &rv)
{
    // Just paste the entry, all pre-checks
    // are done in paymentserver.cpp.
    pasteEntry(rv);
    return true;
}

void ZSendCoinsDialog::setBalance(const interfaces::WalletBalances& balances)
{
    if(model && model->getOptionsModel())
    {
        CAmount balance = balances.balance;
        if (model->privateKeysDisabled()) {
            balance = balances.watch_only_balance;
            ui->labelBalanceName->setText(tr("Watch-only balance:"));
        }
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance));
    }
}

void ZSendCoinsDialog::updateDisplayUnit()
{
    setBalance(model->wallet().getBalances());
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateFeeLabel();
}

void ZSendCoinsDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void ZSendCoinsDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void ZSendCoinsDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void ZSendCoinsDialog::updateFeeSectionControls()
{
    ui->labelCustomFeeWarning  ->setEnabled(ui->checkBoxCustomFee->isChecked());
    ui->customFee              ->setEnabled(ui->checkBoxCustomFee->isChecked());
}

void ZSendCoinsDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    if (ui->checkBoxCustomFee->isChecked())
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value()));
    else
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), 10000));
}

void ZSendCoinsDialog::updateInputControlState(CInputControl& ctrl)
{
    if (ui->checkBoxCustomFee->isChecked()) {
        ctrl.m_fee = CAmount(ui->customFee->value());
    } else {
        ctrl.m_fee.reset();
    }
}

void ZSendCoinsDialog::updateFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    CInputControl input_control;
    updateInputControlState(input_control);
    input_control.m_fee.reset(); // Explicitly use only fee estimation rate for smart fee labels

    updateFeeMinimizedLabel();
}

void ZSendCoinsDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // All status values are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::DuplicateAddress:
        msgParams.first = tr("Duplicate address found: addresses should only be used once each.");
        break;
    // included to prevent a compiler warning.
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("ZSend Coins"), msgParams.first, msgParams.second);
}

// Input Control: copy label "Quantity" to clipboard
void ZSendCoinsDialog::inputControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelInputControlQuantity->text());
}

// Input Control: copy label "Amount" to clipboard
void ZSendCoinsDialog::inputControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelInputControlAmount->text().left(ui->labelInputControlAmount->text().indexOf(" ")));
}

// Input Control: copy label "Fee" to clipboard
void ZSendCoinsDialog::inputControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelInputControlFee->text().left(ui->labelInputControlFee->text().indexOf(" ")));
}

// Input Control: copy label "After fee" to clipboard
void ZSendCoinsDialog::inputControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelInputControlAfterFee->text().left(ui->labelInputControlAfterFee->text().indexOf(" ")));
}

// Input Control: button inputs -> show actual coin control dialog
void ZSendCoinsDialog::inputControlButtonClicked()
{
    InputControlDialog dlg(platformStyle);
    dlg.setModel(model);
    dlg.exec();
    inputControlUpdateLabels();
}

// Input Control: update labels
void ZSendCoinsDialog::inputControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    updateInputControlState(*InputControlDialog::inputControl());

    // set pay amounts
    InputControlDialog::payAmounts.clear();

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        ZSendCoinsEntry *entry = qobject_cast<ZSendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            InputControlDialog::payAmounts.append(rcp.amount);
        }
    }

    if (InputControlDialog::inputControl()->HasSelected())
    {
        // actual coin control calculation
        InputControlDialog::updateLabels(model, this);

        // show coin control stats
        ui->labelInputControlManuallySelected->hide();
        ui->widgetInputControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelInputControlManuallySelected->show();
        ui->widgetInputControl->hide();
        ui->labelInputControlInsuffFunds->hide();
    }
}

ZSendConfirmationDialog::ZSendConfirmationDialog(const QString& title, const QString& text, const QString& informative_text, const QString& detailed_text, int _secDelay, QWidget* parent)
    : QMessageBox(parent), secDelay(_secDelay)
{
    setIcon(QMessageBox::Question);
    setWindowTitle(title); // On macOS, the window title is ignored (as required by the macOS Guidelines).
    setText(text);
    setInformativeText(informative_text);
    setDetailedText(detailed_text);
    setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    updateYesButton();
    connect(&countDownTimer, &QTimer::timeout, this, &ZSendConfirmationDialog::countDown);
}

int ZSendConfirmationDialog::exec()
{
    updateYesButton();
    countDownTimer.start(1000);
    return QMessageBox::exec();
}

void ZSendConfirmationDialog::countDown()
{
    secDelay--;
    updateYesButton();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void ZSendConfirmationDialog::updateYesButton()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(tr("Send") + " (" + QString::number(secDelay) + ")");
    }
    else
    {
        yesButton->setEnabled(true);
        yesButton->setText(tr("Send"));
    }
}

ZSendResultDialog::ZSendResultDialog(const QString& title, const QString& text, QWidget* parent)
    : QMessageBox(parent)
{
    setIcon(QMessageBox::Information);
    setWindowTitle(title); // On macOS, the window title is ignored (as required by the macOS Guidelines).
    setText(text);
    setStandardButtons(QMessageBox::Close);
    setDefaultButton(QMessageBox::Close);
}

int ZSendResultDialog::exec()
{
    return QMessageBox::exec();
}
