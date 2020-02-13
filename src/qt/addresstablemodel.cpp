// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/addresstablemodel.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <key_io.h>
#include <wallet/wallet.h>

#include <algorithm>

#include <QFont>
#include <QDebug>

const QString AddressTableModel::Send = "S";
const QString AddressTableModel::Receive = "R";

const QString AddressTableModel::Base = "base";
const QString AddressTableModel::Sprout = "sprout";
const QString AddressTableModel::Sapling = "sapling";

const QString AddressTableModel::All = "A";
const QString AddressTableModel::Transparent = "T";
const QString AddressTableModel::Shielded = "Z";

struct AddressTableEntry
{
    enum Type {
        Sending,
        Receiving,
        Hidden /* QSortFilterProxyModel will filter these out */
    };

    Type type;
    QString addressbook;
    QString label;
    QString address;

    AddressTableEntry() {}
    AddressTableEntry(Type _type, const QString &_addressbook, const QString &_label, const QString &_address):
        type(_type), addressbook(_addressbook), label(_label), address(_address) {}
};

struct AddressTableEntryLessThan
{
    bool operator()(const AddressTableEntry &a, const AddressTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const AddressTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const AddressTableEntry &b) const
    {
        return a < b.address;
    }
};

/* Determine address type from address purpose */
static AddressTableEntry::Type translateTransactionType(const QString &strPurpose, bool isMine)
{
    AddressTableEntry::Type addressType = AddressTableEntry::Hidden;
    // "refund" addresses aren't shown, and change addresses aren't in mapAddressBook at all.
    if (strPurpose == "send")
        addressType = AddressTableEntry::Sending;
    else if (strPurpose == "receive")
        addressType = AddressTableEntry::Receiving;
    else if (strPurpose == "unknown" || strPurpose == "") // if purpose not set, guess
        addressType = (isMine ? AddressTableEntry::Receiving : AddressTableEntry::Sending);
    return addressType;
}

// Private implementation
class AddressTablePriv
{
public:
    QList<AddressTableEntry> cachedAddressTable;
    AddressTableModel *parent;

    explicit AddressTablePriv(AddressTableModel *_parent):
        parent(_parent) {}

    void refreshAddressTable(interfaces::Wallet& wallet)
    {
        cachedAddressTable.clear();
        {
            // Transparent address
            for (const auto& address : wallet.getAddresses())
            {
                AddressTableEntry::Type addressType = translateTransactionType(
                        QString::fromStdString(address.purpose), address.is_mine);
                cachedAddressTable.append(AddressTableEntry(addressType, AddressTableModel::Base,
                                  QString::fromStdString(address.name),
                                  QString::fromStdString(EncodeDestination(address.dest))));
            }

            // Sprout addresses
            for (const auto& address : wallet.getSproutAddresses())
            {
                AddressTableEntry::Type addressType = translateTransactionType(
                        QString::fromStdString(address.purpose), address.is_mine);
                cachedAddressTable.append(AddressTableEntry(addressType, AddressTableModel::Sprout,
                                  QString::fromStdString(address.name),
                                  QString::fromStdString(EncodePaymentAddress(address.dest))));
            }

            // Sapling addresses
            for (const auto& address : wallet.getSaplingAddresses())
            {
                AddressTableEntry::Type addressType = translateTransactionType(
                        QString::fromStdString(address.purpose), address.is_mine);
                cachedAddressTable.append(AddressTableEntry(addressType, AddressTableModel::Sapling,
                                  QString::fromStdString(address.name),
                                  QString::fromStdString(EncodePaymentAddress(address.dest))));
            }
        }
        // std::lower_bound() and std::upper_bound() require our cachedAddressTable list to be sorted in asc order
        // Even though the map is already sorted this re-sorting step is needed because the originating map
        // is sorted by binary address, not by base58() address.
        std::sort(cachedAddressTable.begin(), cachedAddressTable.end(), AddressTableEntryLessThan());
    }

    void updateEntry(const QString &addressbook, const QString &address, const QString &label, bool isMine, const QString &purpose, int status)
    {
        // Find address / label in model
        QList<AddressTableEntry>::iterator lower = std::lower_bound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        QList<AddressTableEntry>::iterator upper = std::upper_bound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        int lowerIndex = (lower - cachedAddressTable.begin());
        int upperIndex = (upper - cachedAddressTable.begin());
        bool inModel = (lower != upper);
        AddressTableEntry::Type newEntryType = translateTransactionType(purpose, isMine);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_NEW, but entry is already in model";
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, addressbook, label, address));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_UPDATED, but entry is not in model";
                break;
            }
            lower->type = newEntryType;
            lower->addressbook = addressbook;
            lower->label = label;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_DELETED, but entry is not in model";
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedAddressTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedAddressTable.size();
    }

    AddressTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedAddressTable.size())
        {
            return &cachedAddressTable[idx];
        }
        else
        {
            return nullptr;
        }
    }
};

AddressTableModel::AddressTableModel(WalletModel *parent) :
    QAbstractTableModel(parent), walletModel(parent)
{
    columns << tr("Label") << tr("Address");
    priv = new AddressTablePriv(this);
    priv->refreshAddressTable(parent->wallet());
}

AddressTableModel::~AddressTableModel()
{
    delete priv;
}

int AddressTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int AddressTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant AddressTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            if(rec->label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->label;
            }
        case Address:
            return rec->address;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == Address)
        {
            font = GUIUtil::fixedPitchFont();
        }
        return font;
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case AddressTableEntry::Sending:
            return Send;
        case AddressTableEntry::Receiving:
            return Receive;
        default: break;
        }
    }
    else if (role == FilterRole)
    {
        if (rec->addressbook == AddressTableModel::Base)
            return Transparent;
        if ((rec->addressbook == AddressTableModel::Sprout) || (rec->addressbook == AddressTableModel::Sapling))
            return Shielded;
    }
    return QVariant();
}

bool AddressTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());
    std::string strPurpose = (rec->type == AddressTableEntry::Sending ? "send" : "receive");
    editStatus = OK;

    if(role == Qt::EditRole)
    {
        if(rec->addressbook == AddressTableModel::Base)
        {
            CTxDestination curAddress = DecodeDestination(rec->address.toStdString());
            if(index.column() == Label)
            {
                // Do nothing, if old label == new label
                if(rec->label == value.toString())
                {
                    editStatus = NO_CHANGES;
                    return false;
                }
                walletModel->wallet().setAddressBook(curAddress, value.toString().toStdString(), strPurpose);
            } else if(index.column() == Address) {
                CTxDestination newAddress = DecodeDestination(value.toString().toStdString());
                // Refuse to set invalid address, set error status and return false
                if(boost::get<CNoDestination>(&newAddress))
                {
                    editStatus = INVALID_ADDRESS;
                    return false;
                }
                // Do nothing, if old address == new address
                else if(newAddress == curAddress)
                {
                    editStatus = NO_CHANGES;
                    return false;
                }
                // Check for duplicate addresses to prevent accidental deletion of addresses, if you try
                // to paste an existing address over another address (with a different label)
                if (walletModel->wallet().getAddress(
                        newAddress, /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return false;
                }
                // Double-check that we're not overwriting a receiving address
                else if(rec->type == AddressTableEntry::Sending)
                {
                    // Remove old entry
                    walletModel->wallet().delAddressBook(curAddress);
                    // Add new entry with new address
                    walletModel->wallet().setAddressBook(newAddress, value.toString().toStdString(), strPurpose);
                }
            }
        }
        else if(rec->addressbook == AddressTableModel::Sprout)
        {
            libzcash::PaymentAddress curAddress = DecodePaymentAddress(rec->address.toStdString());
            if(index.column() == Label)
            {
                // Do nothing, if old label == new label
                if(rec->label == value.toString())
                {
                    editStatus = NO_CHANGES;
                    return false;
                }
                walletModel->wallet().setSproutAddressBook(curAddress, value.toString().toStdString(), strPurpose);
            } else if(index.column() == Address) {
                libzcash::PaymentAddress newAddress = DecodePaymentAddress(value.toString().toStdString());
                // Refuse to set invalid address, set error status and return false
                if(boost::get<libzcash::InvalidEncoding>(&newAddress))
                {
                    editStatus = INVALID_ADDRESS;
                    return false;
                }
                // Do nothing, if old address == new address
                else if(newAddress == curAddress)
                {
                    editStatus = NO_CHANGES;
                    return false;
                }
                // Check for duplicate addresses to prevent accidental deletion of addresses, if you try
                // to paste an existing address over another address (with a different label)
                if (walletModel->wallet().getSproutAddress(
                        newAddress, /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return false;
                }
                // Double-check that we're not overwriting a receiving address
                else if(rec->type == AddressTableEntry::Sending)
                {
                    // Remove old entry
                    walletModel->wallet().delSproutAddressBook(curAddress);
                    // Add new entry with new address
                    walletModel->wallet().setSproutAddressBook(newAddress, value.toString().toStdString(), strPurpose);
                }
            }
        }
        else if(rec->addressbook == AddressTableModel::Sapling)
        {
            libzcash::PaymentAddress curAddress = DecodePaymentAddress(rec->address.toStdString());
            if(index.column() == Label)
            {
                // Do nothing, if old label == new label
                if(rec->label == value.toString())
                {
                    editStatus = NO_CHANGES;
                    return false;
                }
                walletModel->wallet().setSaplingAddressBook(curAddress, value.toString().toStdString(), strPurpose);
            } else if(index.column() == Address) {
                libzcash::PaymentAddress newAddress = DecodePaymentAddress(value.toString().toStdString());
                // Refuse to set invalid address, set error status and return false
                if(boost::get<libzcash::InvalidEncoding>(&newAddress))
                {
                    editStatus = INVALID_ADDRESS;
                    return false;
                }
                // Do nothing, if old address == new address
                else if(newAddress == curAddress)
                {
                    editStatus = NO_CHANGES;
                    return false;
                }
                // Check for duplicate addresses to prevent accidental deletion of addresses, if you try
                // to paste an existing address over another address (with a different label)
                if (walletModel->wallet().getSaplingAddress(
                        newAddress, /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return false;
                }
                // Double-check that we're not overwriting a receiving address
                else if(rec->type == AddressTableEntry::Sending)
                {
                    // Remove old entry
                    walletModel->wallet().delSaplingAddressBook(curAddress);
                    // Add new entry with new address
                    walletModel->wallet().setSaplingAddressBook(newAddress, value.toString().toStdString(), strPurpose);
                }
            }
        }
        return true;
    }
    return false;
}

QVariant AddressTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole && section < columns.size())
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags AddressTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid()) return Qt::NoItemFlags;

    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can edit address and label for sending addresses,
    // and only label for receiving addresses.
    if(rec->type == AddressTableEntry::Sending ||
      (rec->type == AddressTableEntry::Receiving && index.column()==Label))
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QModelIndex AddressTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    AddressTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void AddressTableModel::updateEntry(const QString &addressbook, const QString &address, const QString &label, bool isMine, const QString &purpose, int status)
{
    // Update address book model from Bitcoin core
    priv->updateEntry(addressbook, address, label, isMine, purpose, status);
}

QString AddressTableModel::addRow(const QString &type, const QString &addressbook, const QString &label, const QString &address, const OutputType address_type)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;

    if(type == Send)
    {
        if(addressbook == AddressTableModel::Base)
        {
            if(!walletModel->validateAddress(address))
            {
                editStatus = INVALID_ADDRESS;
                return QString();
            }
            // Check for duplicate addresses
            {
                if (walletModel->wallet().getAddress(
                        DecodeDestination(strAddress), /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return QString();
                }
            }

            // Add entry
            walletModel->wallet().setAddressBook(DecodeDestination(strAddress), strLabel, "send");
        }
        else if(addressbook == AddressTableModel::Sprout)
        {
            if(!walletModel->validatePaymentAddress(address))
            {
                editStatus = INVALID_ADDRESS;
                return QString();
            }
            // Check for duplicate addresses
            {
                if (walletModel->wallet().getSproutAddress(
                        DecodePaymentAddress(strAddress), /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return QString();
                }
            }

            // Add entry
            walletModel->wallet().setSproutAddressBook(DecodePaymentAddress(strAddress), strLabel, "send");
        }
        else if(addressbook == AddressTableModel::Sapling)
        {
            if(!walletModel->validatePaymentAddress(address))
            {
                editStatus = INVALID_ADDRESS;
                return QString();
            }
            // Check for duplicate addresses
            {
                if (walletModel->wallet().getSaplingAddress(
                        DecodePaymentAddress(strAddress), /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return QString();
                }
            }

            // Add entry
            walletModel->wallet().setSaplingAddressBook(DecodePaymentAddress(strAddress), strLabel, "send");
        }
    }
    else if(type == Receive)
    {
        if(addressbook == AddressTableModel::Base)
        {
            // Generate a new address to associate with given label
            CTxDestination dest;
            if(!walletModel->wallet().getNewDestination(address_type, strLabel, dest))
            {
                WalletModel::UnlockContext ctx(walletModel->requestUnlock());
                if(!ctx.isValid())
                {
                    // Unlock wallet failed or was cancelled
                    editStatus = WALLET_UNLOCK_FAILURE;
                    return QString();
                }
                if(!walletModel->wallet().getNewDestination(address_type, strLabel, dest))
                {
                    editStatus = KEY_GENERATION_FAILURE;
                    return QString();
                }
            }
            strAddress = EncodeDestination(dest);
        }
        else if(addressbook == AddressTableModel::Sprout)
        {
            // Generate a new address to associate with given label
            libzcash::PaymentAddress dest;
            if(!walletModel->wallet().getNewSproutDestination(strLabel, dest))
            {
                WalletModel::UnlockContext ctx(walletModel->requestUnlock());
                if(!ctx.isValid())
                {
                    // Unlock wallet failed or was cancelled
                    editStatus = WALLET_UNLOCK_FAILURE;
                    return QString();
                }
                if(!walletModel->wallet().getNewSproutDestination(strLabel, dest))
                {
                    editStatus = KEY_GENERATION_FAILURE;
                    return QString();
                }
            }
            strAddress = EncodePaymentAddress(dest);
        }
        else if(addressbook == AddressTableModel::Sapling)
        {
            // Generate a new address to associate with given label
            libzcash::PaymentAddress dest;
            if(!walletModel->wallet().getNewSaplingDestination(strLabel, dest))
            {
                WalletModel::UnlockContext ctx(walletModel->requestUnlock());
                if(!ctx.isValid())
                {
                    // Unlock wallet failed or was cancelled
                    editStatus = WALLET_UNLOCK_FAILURE;
                    return QString();
                }
                if(!walletModel->wallet().getNewSaplingDestination(strLabel, dest))
                {
                    editStatus = KEY_GENERATION_FAILURE;
                    return QString();
                }
            }
            strAddress = EncodePaymentAddress(dest);
        }
    }
    else
    {
        return QString();
    }
    return QString::fromStdString(strAddress);
}

bool AddressTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);
    AddressTableEntry *rec = priv->index(row);
    if(count != 1 || !rec || rec->type == AddressTableEntry::Receiving)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }
    if(rec->addressbook == AddressTableModel::Base)
        walletModel->wallet().delAddressBook(DecodeDestination(rec->address.toStdString()));
    else if(rec->addressbook == AddressTableModel::Sprout)
        walletModel->wallet().delSproutAddressBook(DecodePaymentAddress(rec->address.toStdString()));
    else if(rec->addressbook == AddressTableModel::Sapling)
        walletModel->wallet().delSaplingAddressBook(DecodePaymentAddress(rec->address.toStdString()));
    return true;
}

QString AddressTableModel::labelForAddress(const QString &address) const
{
    std::string name;
    if (getAddressData(address, &name, /* purpose= */ nullptr)) {
        return QString::fromStdString(name);
    }
    return QString();
}

QString AddressTableModel::purposeForAddress(const QString &address) const
{
    std::string purpose;
    if (getAddressData(address, /* name= */ nullptr, &purpose)) {
        return QString::fromStdString(purpose);
    }
    return QString();
}

bool AddressTableModel::getAddressData(const QString &address,
        std::string* name,
        std::string* purpose) const {
    bool ret = false;

    std::string strAddress = address.toStdString();
    QString addressbook;

    if(IsValidDestinationString(strAddress))
        addressbook = AddressTableModel::Base;
    else
    {
        libzcash::PaymentAddress dest = DecodePaymentAddress(strAddress);
        if(boost::get<libzcash::SproutPaymentAddress>(&dest))
            addressbook = AddressTableModel::Sprout;
        else if(boost::get<libzcash::SaplingPaymentAddress>(&dest))
            addressbook = AddressTableModel::Sapling;
    }

    if(addressbook == AddressTableModel::Base)
    {
        CTxDestination destination = DecodeDestination(address.toStdString());
        ret = walletModel->wallet().getAddress(destination, name, /* is_mine= */ nullptr, purpose);
    }
    else if(addressbook == AddressTableModel::Sprout)
    {
        libzcash::PaymentAddress destination = DecodePaymentAddress(address.toStdString());
        ret = walletModel->wallet().getSproutAddress(destination, name, /* is_mine= */ nullptr, purpose);
    }
    else if(addressbook == AddressTableModel::Sapling)
    {
        libzcash::PaymentAddress destination = DecodePaymentAddress(address.toStdString());
        ret = walletModel->wallet().getSaplingAddress(destination, name, /* is_mine= */ nullptr, purpose);
    }
    return ret;
}

int AddressTableModel::lookupAddress(const QString &address) const
{
    QModelIndexList lst = match(index(0, Address, QModelIndex()),
                                Qt::EditRole, address, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

OutputType AddressTableModel::GetDefaultAddressType() const { return walletModel->wallet().getDefaultAddressType(); };

void AddressTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}
