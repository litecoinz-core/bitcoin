// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BITCOINAMOUNTLABEL_H
#define BITCOIN_QT_BITCOINAMOUNTLABEL_H

#include <QLabel>
#include <QString>
#include <QWidget>

/**
 * Widget for displaying bitcoin amounts.
 */
class BitcoinAmountLabel : public QLabel
{
    Q_OBJECT

public:
    explicit BitcoinAmountLabel(QWidget* parent = nullptr);
    void setText(const QString& newText);

Q_SIGNALS:
    void aboutToTogglePrivacy();

public Q_SLOTS:
    void changePrivacyMode(bool privacy);

protected:
    void mousePressEvent(QMouseEvent* ev) override;

private:
    QString cache{};
};

#endif // BITCOIN_QT_BITCOINAMOUNTLABEL_H
