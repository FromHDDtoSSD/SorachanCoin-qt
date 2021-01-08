// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRCODEDIALOG_H
#define QRCODEDIALOG_H

#include <QDialog>
#include <QImage>

namespace Ui {
    class QRCodeDialog;
}
class OptionsModel;

class QRCodeDialog : public QDialog
{
    Q_OBJECT
private:
    QRCodeDialog(const QRCodeDialog &)=delete;
    QRCodeDialog &operator=(const QRCodeDialog &)=delete;
    QRCodeDialog(QRCodeDialog &&)=delete;
    QRCodeDialog &operator=(QRCodeDialog &&)=delete;
public:
    explicit QRCodeDialog(const QString &addr, const QString &label, bool enableReq, QWidget *parent = 0);
    ~QRCodeDialog();

    void setModel(OptionsModel *model);

private slots:
    void on_lnReqAmount_textChanged();
    void on_lnLabel_textChanged();
    void on_lnMessage_textChanged();
    void on_btnSaveAs_clicked();
    void on_chkReqPayment_toggled(bool fChecked);

    void updateDisplayUnit();

private:
    Ui::QRCodeDialog *ui;
    OptionsModel *model;
    QString address;
    QImage myImage;

    void genCode();
    QString getURI();
};

#endif // QRCODEDIALOG_H
