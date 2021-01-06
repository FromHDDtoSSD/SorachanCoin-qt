// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CSVMODELWRITER_H
#define CSVMODELWRITER_H

#include <QObject>
#include <QList>

QT_BEGIN_NAMESPACE
class QAbstractItemModel;
QT_END_NAMESPACE

/** Export a Qt table model to a CSV file. This is useful for analyzing or post-processing the data in
    a spreadsheet.
 */
class CSVModelWriter : public QObject
{
    Q_OBJECT
private:
    CSVModelWriter(const CSVModelWriter &)=delete;
    CSVModelWriter &operator=(const CSVModelWriter &)=delete;
    CSVModelWriter(CSVModelWriter &&)=delete;
    CSVModelWriter &operator=(CSVModelWriter &&)=delete;
public:
    explicit CSVModelWriter(const QString &filename, QObject *parent = nullptr);

    void setModel(const QAbstractItemModel *model);
    void addColumn(const QString &title, int column, int role=Qt::EditRole);

    /** Perform export of the model to CSV.
        @returns true on success, false otherwise
    */
    bool write();

private:
    QString filename;
    const QAbstractItemModel *model;

    struct Column
    {
        QString title;
        int column;
        int role;
    };
    QList<Column> columns;

signals:

public slots:

};

#endif // CSVMODELWRITER_H
