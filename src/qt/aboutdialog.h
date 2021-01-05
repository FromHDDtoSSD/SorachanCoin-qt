// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ABOUTDIALOG_H
#define ABOUTDIALOG_H

#include <QWidget>

namespace Ui {
    class AboutDialog;
}
class ClientModel;

class AboutDialog : public QWidget
{
    Q_OBJECT
private:
    // AboutDialog()=delete; Call by explicit AboutDialog(QWidget *parent = 0);
    AboutDialog(const AboutDialog &)=delete;
    AboutDialog &operator=(const AboutDialog &)=delete;
    AboutDialog(AboutDialog &&)=delete;
    AboutDialog &operator=(AboutDialog &&)=delete;
public:
    explicit AboutDialog(QWidget *parent = 0);
    ~AboutDialog();
    void setModel(ClientModel *model);
private:
    Ui::AboutDialog *ui;
    void keyPressEvent(QKeyEvent *);
private slots:
    void on_buttonBox_accepted();
};

#endif // ABOUTDIALOG_H
