// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MINTINGFILTERPROXY_H
#define MINTINGFILTERPROXY_H

#include <QSortFilterProxyModel>

class MintingFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT
private:
    MintingFilterProxy(const MintingFilterProxy &)=delete;
    MintingFilterProxy &operator=(const MintingFilterProxy &)=delete;
    MintingFilterProxy(MintingFilterProxy &&)=delete;
    MintingFilterProxy &operator=(MintingFilterProxy &&)=delete;
public:
    explicit MintingFilterProxy(QObject *parent = nullptr);
};

#endif // MINTINGFILTERPROXY_H
