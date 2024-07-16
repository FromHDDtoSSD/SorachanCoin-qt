// Copyright (c) 2018-2024 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GETCIPHER_WIDGET_H
#define GETCIPHER_WIDGET_H

#include <qt/rpcconsole.h>
#include <ui_interface.h>

class QMB : public QObject
{
    Q_OBJECT
public:
    enum status {
        M_OK,
        M_ERROR
    };

    QMB() = delete;
    QMB(status s) {
        if(s == M_OK) {
            qbox.setWindowTitle(_("Confirmation").c_str());
            qbox.setIcon(QMessageBox::Information);
            qbox.setStandardButtons(QMessageBox::Ok);
            qbox.setDefaultButton(QMessageBox::Ok);
        } else if (s == M_ERROR) {
            qbox.setWindowTitle(_("Error").c_str());
            qbox.setIcon(QMessageBox::Critical);
            qbox.setStandardButtons(QMessageBox::Ok);
            qbox.setDefaultButton(QMessageBox::Ok);
        }
    }

    QMB &setText(const std::string &text) {
        qbox.setText(QString(text.c_str()));
        return *this;
    }

    int exec() {
        qbox.exec();
        return 0;
    }

private:
    QMessageBox qbox;
};

class CipherWidget : public QObject
{
    Q_OBJECT
public slots:
    void showMessagebox(const std::string &str, QMB::status status);
};

#endif // GETCIPHER_WIDGET_H
