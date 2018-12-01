#ifndef MINTINGFILTERPROXY_H
#define MINTINGFILTERPROXY_H

#include <QSortFilterProxyModel>

class MintingFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT
private:
    MintingFilterProxy(const MintingFilterProxy &); // {}
    MintingFilterProxy &operator=(const MintingFilterProxy &); // {}
public:
    explicit MintingFilterProxy(QObject *parent = 0);
};

#endif // MINTINGFILTERPROXY_H
//@
