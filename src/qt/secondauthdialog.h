// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SECONDAUTHDIALOG_H
#define SECONDAUTHDIALOG_H

#include <QWidget>

namespace Ui {
    class SecondAuthDialog;
}
class WalletModel;

QT_BEGIN_NAMESPACE
QT_END_NAMESPACE

class SecondAuthDialog : public QWidget
{
    Q_OBJECT
private:
    SecondAuthDialog(const SecondAuthDialog &)=delete;
    SecondAuthDialog &operator=(const SecondAuthDialog &)=delete;
    SecondAuthDialog(SecondAuthDialog &&)=delete;
    SecondAuthDialog &operator=(SecondAuthDialog &&)=delete;
public:
    explicit SecondAuthDialog(QWidget *parent = nullptr);
    ~SecondAuthDialog();

    void setModel(WalletModel *model);
    void setAddress(QString address);

protected:
    bool eventFilter(QObject *object, QEvent *event);
    void keyPressEvent(QKeyEvent *);

private:
    Ui::SecondAuthDialog *ui;
    WalletModel *model;

private slots:
    /* sign */
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();
    void on_signMessageButton_clicked();
    void on_copySignatureButton_clicked();
    void on_clearButton_clicked();
};

#endif // SECONDAUTHDIALOG_H
