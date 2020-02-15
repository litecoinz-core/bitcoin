// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/shieldcoinbasedialog.h>
#include <qt/forms/ui_shieldcoinbasedialog.h>

#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/inputcontroldialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/sendcoinsdialog.h>

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

#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>

ShieldCoinbaseDialog::ShieldCoinbaseDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ShieldCoinbaseDialog),
    clientModel(nullptr),
    model(nullptr),
    fFeeMinimized(true),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->clearButton->setIcon(QIcon());
        ui->shieldButton->setIcon(QIcon());
        ui->addressBookButton->setIcon(QIcon());
        ui->deleteButton->setIcon(QIcon());
    } else {
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->shieldButton->setIcon(_platformStyle->SingleColorIcon(":/icons/send"));
        ui->addressBookButton->setIcon(_platformStyle->SingleColorIcon(":/icons/address-book"));
        ui->deleteButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
    }

    connect(ui->clearButton, &QPushButton::clicked, this, &ShieldCoinbaseDialog::clear);

    // Input Control
    connect(ui->pushButtonInputControl, &QPushButton::clicked, this, &ShieldCoinbaseDialog::inputControlButtonClicked);

    // Input Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &ShieldCoinbaseDialog::inputControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &ShieldCoinbaseDialog::inputControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &ShieldCoinbaseDialog::inputControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &ShieldCoinbaseDialog::inputControlClipboardAfterFee);
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

    // Shield Limit section
    ui->sliderShieldLimit->setRange(0, 500);
    ui->sliderShieldLimit->setSingleStep(10);
    if (!settings.contains("nShieldLimitSliderPosition"))
        settings.setValue("nShieldLimitSliderPosition", 50);
    ui->sliderShieldLimit->setValue(settings.value("nShieldLimitSliderPosition").toInt());
    connect(ui->sliderShieldLimit, SIGNAL(valueChanged(int)), this, SLOT(updateShieldLimitLabel()));

    // Connect signals
    connect(ui->deleteButton, &QPushButton::clicked, this, &ShieldCoinbaseDialog::deleteClicked);
    connect(ui->checkboxUseMaxUtxos, &QCheckBox::stateChanged, this, &ShieldCoinbaseDialog::useMaxUtxosChecked);

    updateShieldLimitLabel();
}

void ShieldCoinbaseDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
}

void ShieldCoinbaseDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        interfaces::WalletBalances balances = _model->wallet().getBalances();
        setBalance(balances);
        connect(_model, &WalletModel::balanceChanged, this, &ShieldCoinbaseDialog::setBalance);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ShieldCoinbaseDialog::updateDisplayUnit);
        updateDisplayUnit();

        // Input Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ShieldCoinbaseDialog::inputControlUpdateLabels);
        inputControlUpdateLabels();

        // fee section
        connect(ui->checkBoxCustomFee, &QCheckBox::stateChanged, this, &ShieldCoinbaseDialog::updateFeeSectionControls);
        connect(ui->checkBoxCustomFee, &QCheckBox::stateChanged, this, &ShieldCoinbaseDialog::inputControlUpdateLabels);
        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &ShieldCoinbaseDialog::inputControlUpdateLabels);
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

ShieldCoinbaseDialog::~ShieldCoinbaseDialog()
{
    QSettings settings;
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nZTransactionFee", (qint64)ui->customFee->value());
    settings.setValue("nShieldLimitSliderPosition", (qint8)ui->sliderShieldLimit->value());

    delete ui;
}

void ShieldCoinbaseDialog::updateShieldLimitLabel()
{
    ui->labelUtxos->setText(QString::number(ui->sliderShieldLimit->value()));
}

void ShieldCoinbaseDialog::on_addressBookButton_clicked()
{
    if(!model)
        return;

    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, AddressBookPage::Shielded, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        QString text = dlg.getReturnValue();
        ui->shieldTo->setText(text);
        ui->shieldTo->setToolTip(text);
    }
}

void ShieldCoinbaseDialog::deleteClicked()
{
    ui->shieldTo->clear();
    ui->shieldTo->setToolTip("The Litecoinz z-address to shield the coinbase to");
    ui->addAsLabel->clear();
}

void ShieldCoinbaseDialog::on_shieldTo_textChanged(const QString &address)
{
    updateLabel(address);
}

void ShieldCoinbaseDialog::on_shieldButton_clicked()
{
    if(!model || !model->getOptionsModel())
        return;

    bool valid = true;

    // generate address string
    QString address = ui->shieldTo->text();
    QString label = ui->addAsLabel->text();

    if (!model->validatePaymentAddress(address))
    {
        ui->shieldTo->setValid(false);
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    // Always use a CInputControl instance
    CInputControl ctrl = *InputControlDialog::inputControl();
    updateInputControlState(ctrl);

    CAmount txFee = model->wallet().getCustomFee(ctrl);
    CAmount amountToShield = 0;

    QString addressFrom = ui->shieldFrom->text();
    if (addressFrom.isEmpty())
    {
        addressFrom = "*";
        amountToShield = model->wallet().getBalances().coinbase_balance - txFee;
    }
    else
    {
        QString afterFee = ui->labelInputControlAfterFee->text().left(ui->labelInputControlAfterFee->text().indexOf(" "));
        valid = BitcoinUnits::parse(model->getOptionsModel()->getDisplayUnit(), afterFee, &amountToShield);
        if(!valid)
            return;
    }

    // Format confirmation message
    QStringList formatted;

    // generate amount string with wallet name in case of multiwallet
    QString amount = BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), amountToShield);
    if (model->isMultiwallet()) {
        amount.append(tr(" from wallet '%1'").arg(GUIUtil::HtmlEscape(model->getWalletName())));
    }

    QString recipientElement;
    {
        if(!label.isEmpty()) // label with address
        {
            recipientElement.append(tr("%1 to '%2'").arg(amount, GUIUtil::HtmlEscape(label)));
            recipientElement.append(QString(" (%1)").arg(address));
        }
        else // just address
        {
            recipientElement.append(tr("%1 to %2").arg(amount, address));
        }
    }
    formatted.append(recipientElement);

    QString questionString = tr("Are you sure you want to shield?");
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
    CAmount totalAmount = amountToShield + txFee;
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
    questionString = questionString.arg("<br /><br />" + formatted.at(0));

    QString informative_text;
    QString detailed_text;

    ShieldConfirmationDialog confirmationDialog(tr("Confirm send coins"), questionString, informative_text, detailed_text, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = static_cast<QMessageBox::StandardButton>(confirmationDialog.result());

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    bool sendStatus = false;

    UniValue params(UniValue::VARR);
    UniValue ret;

    try {
        params.push_back(addressFrom.toStdString());
        params.push_back(address.toStdString());
        params.push_back(ValueFromAmount(txFee));
        params.push_back(ui->sliderShieldLimit->value());

        JSONRPCRequest request;
        request.params = params;
        request.fHelp = false;

        ret = z_shieldcoinbase(request);

        sendStatus = true;
    } catch (std::exception &e) {
        qFatal("Error %s ", e.what());
    } catch (...) {
        qFatal("Error <unknown>");
    }

    try {
        UniValue ret1 = find_value(ret, "remainingUTXOs");
        UniValue ret2 = find_value(ret, "remainingValue");
        UniValue ret3 = find_value(ret, "shieldingUTXOs");
        UniValue ret4 = find_value(ret, "shieldingValue");
        UniValue ret5 = find_value(ret, "opid");

        QString resultString = tr("Shielding operation was submitted in background.");

        resultString.append("<table style='width:100%;'>");
        resultString.append("<br />");

        resultString.append("<tr>");
        resultString.append("<td style='width:50%; white-space:nowrap;'><b>" + tr("remainingUTXOs : ") + "</b></td>");
        resultString.append("<td style='width:50%; white-space:nowrap;'>" + QString::number(ret1.get_int()) + "<td>");
        resultString.append("</tr>");

        resultString.append("<tr>");
        resultString.append("<td style='width:50%; white-space:nowrap;'><b>" + tr("remainingValue : ") + "</b></td>");
        resultString.append("<td style='width:50%; white-space:nowrap;'>" + BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), AmountFromValue(ret2)) + "<td>");
        resultString.append("</tr>");

        resultString.append("<tr>");
        resultString.append("<td style='width:50%; white-space:nowrap;'><b>" + tr("shieldingUTXOs : ") + "</b></td>");
        resultString.append("<td style='width:50%; white-space:nowrap;'>" + QString::number(ret3.get_int()) + "<td>");
        resultString.append("</tr>");

        resultString.append("<tr>");
        resultString.append("<td style='width:50%; white-space:nowrap;'><b>" + tr("shieldingValue : ") + "</b></td>");
        resultString.append("<td style='width:50%; white-space:nowrap;'>" + BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), AmountFromValue(ret4)) + "<td>");
        resultString.append("</tr>");

        resultString.append("<tr>");
        resultString.append("<td colspan=2><hr /></td>");
        resultString.append("</tr>");

        resultString.append("<tr>");
        resultString.append("<td style='width:50%; white-space:nowrap;'><b>" + tr("opid : ") + "</b></td>");
        resultString.append("<td style='width:50%; white-space:nowrap;'>" + QString::fromStdString(ret5.get_str()) + "<td>");
        resultString.append("</tr>");

        resultString.append("</table>");

        ShieldResultDialog resultDialog(tr("Shield operation submitted"), resultString, this);
        resultDialog.exec();
    } catch (std::exception &e) {
        qDebug("Error %s ", e.what());
        QMessageBox msgBox("", e.what(), QMessageBox::Critical, 0, 0, 0, this, Qt::WindowTitleHint | Qt::WindowSystemMenuHint);
        msgBox.exec();
    } catch (...) {
        qFatal("Error <unknown>");
        QMessageBox msgBox("", "Error <unknown>", QMessageBox::Critical, 0, 0, 0, this, Qt::WindowTitleHint | Qt::WindowSystemMenuHint);
        msgBox.exec();
    }

    if (sendStatus)
    {
        accept();
        InputControlDialog::inputControl()->UnSelect();
        inputControlUpdateLabels();
        Q_EMIT coinsSent();
    }
}

void ShieldCoinbaseDialog::clear()
{
    // Clear input control settings
    InputControlDialog::inputControl()->UnSelect();
    inputControlUpdateLabels();

    ui->shieldFrom->clear();
    ui->shieldTo->clear();
    ui->addAsLabel->clear();
    ui->checkboxUseMaxUtxos->setChecked(false);

    updateTabsAndLabels();
}

void ShieldCoinbaseDialog::reject()
{
    clear();
}

void ShieldCoinbaseDialog::accept()
{
    clear();
}

void ShieldCoinbaseDialog::updateTabsAndLabels()
{
    inputControlUpdateLabels();
}

void ShieldCoinbaseDialog::setBalance(const interfaces::WalletBalances& balances)
{
    if(model && model->getOptionsModel())
    {
        CAmount balance = balances.coinbase_balance;
        if (model->privateKeysDisabled()) {
            balance = balances.watch_only_coinbase_balance;
            ui->labelCoinbaseBalanceName->setText(tr("Watch-only coinbase balance:"));
        }
        ui->labelCoinbaseBalance->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance));
    }
}

void ShieldCoinbaseDialog::updateDisplayUnit()
{
    setBalance(model->wallet().getBalances());
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateFeeLabel();
}

bool ShieldCoinbaseDialog::updateLabel(const QString &address)
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
    else
    {
        ui->addAsLabel->clear();
    }

    return false;
}

void ShieldCoinbaseDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void ShieldCoinbaseDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void ShieldCoinbaseDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void ShieldCoinbaseDialog::updateFeeSectionControls()
{
    ui->labelCustomFeeWarning  ->setEnabled(ui->checkBoxCustomFee->isChecked());
    ui->customFee              ->setEnabled(ui->checkBoxCustomFee->isChecked());
}

void ShieldCoinbaseDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    if (ui->checkBoxCustomFee->isChecked())
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value()));
    else
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), 10000));
}

void ShieldCoinbaseDialog::updateInputControlState(CInputControl& ctrl)
{
    if (ui->checkBoxCustomFee->isChecked()) {
        ctrl.m_fee = CAmount(ui->customFee->value());
    } else {
        ctrl.m_fee.reset();
    }
}

void ShieldCoinbaseDialog::updateFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    CInputControl input_control;
    updateInputControlState(input_control);
    input_control.m_fee.reset(); // Explicitly use only fee estimation rate for smart fee labels

    updateFeeMinimizedLabel();
}

// Input Control: copy label "Quantity" to clipboard
void ShieldCoinbaseDialog::inputControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelInputControlQuantity->text());
}

// Input Control: copy label "Amount" to clipboard
void ShieldCoinbaseDialog::inputControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelInputControlAmount->text().left(ui->labelInputControlAmount->text().indexOf(" ")));
}

// Input Control: copy label "Fee" to clipboard
void ShieldCoinbaseDialog::inputControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelInputControlFee->text().left(ui->labelInputControlFee->text().indexOf(" ")));
}

// Input Control: copy label "After fee" to clipboard
void ShieldCoinbaseDialog::inputControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelInputControlAfterFee->text().left(ui->labelInputControlAfterFee->text().indexOf(" ")));
}

// checkbox use max utxos
void ShieldCoinbaseDialog::useMaxUtxosChecked(int state)
{
    QSettings settings;
    if (state == Qt::Checked)
        ui->sliderShieldLimit->setValue(0);
    else
        ui->sliderShieldLimit->setValue(settings.value("nShieldLimitSliderPosition").toInt());

    ui->sliderShieldLimit->setEnabled(!ui->checkboxUseMaxUtxos->isChecked());
}

// Input Control: button inputs -> show actual input control dialog
void ShieldCoinbaseDialog::inputControlButtonClicked()
{
    InputControlDialog dlg(platformStyle, true, true);
    dlg.setModel(model);
    dlg.exec();
    inputControlUpdateLabels();
}

// Input Control: update labels
void ShieldCoinbaseDialog::inputControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    updateInputControlState(*InputControlDialog::inputControl());

    // set pay amounts
    InputControlDialog::payAmounts.clear();

    if (InputControlDialog::inputControl()->HasSelected())
    {
        // actual input control calculation
        InputControlDialog::updateLabels(model, this);

        // show input control stats
        ui->labelInputControlAutomaticallySelected->hide();
        ui->widgetInputControl->show();
        ui->widgetInputControl2->show();
    }
    else
    {
        // hide input control stats
        ui->labelInputControlAutomaticallySelected->show();
        ui->widgetInputControl->hide();
        ui->widgetInputControl2->hide();
        ui->labelInputControlInsuffFunds->hide();
    }
}

ShieldConfirmationDialog::ShieldConfirmationDialog(const QString& title, const QString& text, const QString& informative_text, const QString& detailed_text, int _secDelay, QWidget* parent)
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
    connect(&countDownTimer, &QTimer::timeout, this, &ShieldConfirmationDialog::countDown);
}

int ShieldConfirmationDialog::exec()
{
    updateYesButton();
    countDownTimer.start(1000);
    return QMessageBox::exec();
}

void ShieldConfirmationDialog::countDown()
{
    secDelay--;
    updateYesButton();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void ShieldConfirmationDialog::updateYesButton()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(tr("Yes") + " (" + QString::number(secDelay) + ")");
    }
    else
    {
        yesButton->setEnabled(true);
        yesButton->setText(tr("Yes"));
    }
}

ShieldResultDialog::ShieldResultDialog(const QString& title, const QString& text, QWidget* parent)
    : QMessageBox(parent)
{
    setIcon(QMessageBox::Information);
    setWindowTitle(title); // On macOS, the window title is ignored (as required by the macOS Guidelines).
    setText(text);
    setStandardButtons(QMessageBox::Close);
    setDefaultButton(QMessageBox::Close);
}

int ShieldResultDialog::exec()
{
    return QMessageBox::exec();
}
