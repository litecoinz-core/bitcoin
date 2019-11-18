// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bitcoinamountlabel.h>

#include <QChar>
#include <QLabel>
#include <QString>
#include <QStringList>

#include <cassert>

namespace {
const QChar space{' '};
const QChar point{'.'};
const QChar mask{'#'};

QString cloak(QString value_and_unit)
{
    const QString unit = space + value_and_unit.split(space).last();
    const QStringList value_parts = value_and_unit.remove(unit).split(point);
    assert(value_parts.size() <= 2);
    QString cloaked = QString(value_parts.first().size() - 1, space) + mask;
    if (value_parts.size() == 2) {
        cloaked += point + QString(value_parts.last().size(), mask);
    }
    return cloaked + unit;
}
} // namespace

BitcoinAmountLabel::BitcoinAmountLabel(QWidget* parent)
    : QLabel(parent)
{
}

void BitcoinAmountLabel::setText(const QString& newText)
{
    if (cache.isEmpty()) {
        QLabel::setText(newText);
    } else {
        cache = newText;
        QLabel::setText(cloak(cache));
    }
}

void BitcoinAmountLabel::changePrivacyMode(bool privacy)
{
    if (privacy && cache.isEmpty()) {
        cache = text();
        QLabel::setText(cloak(cache));
    } else if (!privacy && !cache.isEmpty()) {
        QLabel::setText(cache);
        cache.clear();
    }
}

void BitcoinAmountLabel::mousePressEvent(QMouseEvent* ev)
{
    Q_EMIT aboutToTogglePrivacy();
    QLabel::mousePressEvent(ev);
}
