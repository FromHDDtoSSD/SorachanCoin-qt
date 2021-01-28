// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONITOREDDATAMAPPER_H
#define MONITOREDDATAMAPPER_H

#include <QDataWidgetMapper>

QT_BEGIN_NAMESPACE
class QWidget;
QT_END_NAMESPACE

/** Data to Widget mapper that watches for edits and notifies listeners when a field is edited.
   This can be used, for example, to enable a commit/apply button in a configuration dialog.
 */
class MonitoredDataMapper : public QDataWidgetMapper
{
    Q_OBJECT
private:
    MonitoredDataMapper(const MonitoredDataMapper &)=delete;
    MonitoredDataMapper &operator=(const MonitoredDataMapper &)=delete;
    MonitoredDataMapper(MonitoredDataMapper &&)=delete;
    MonitoredDataMapper &operator=(MonitoredDataMapper &&)=delete;
public:
    explicit MonitoredDataMapper(QObject *parent = nullptr);

    void addMapping(QWidget *widget, int section);
    void addMapping(QWidget *widget, int section, const QByteArray &propertyName);
private:
    void addChangeMonitor(QWidget *widget);

signals:
    void viewModified();
};

#endif // MONITOREDDATAMAPPER_H
