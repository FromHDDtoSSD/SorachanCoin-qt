// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OPTIONSDIALOG_H
#define OPTIONSDIALOG_H

#include <QWidget>

namespace Ui {
    class OptionsDialog;
}
class OptionsModel;
class MonitoredDataMapper;
class QValidatedLineEdit;

/** Preferences dialog. */
class OptionsDialog : public QWidget
{
    Q_OBJECT
private:
    OptionsDialog(const OptionsDialog &)=delete;
    OptionsDialog &operator=(const OptionsDialog &)=delete;
    OptionsDialog(OptionsDialog &&)=delete;
    OptionsDialog &operator=(OptionsDialog &&)=delete;
public:
    explicit OptionsDialog(QWidget *parent = 0);
    ~OptionsDialog();

    void setModel(OptionsModel *model);
    void setMapper();

protected:
    bool eventFilter(QObject *object, QEvent *event);
    void keyPressEvent(QKeyEvent *);

private slots:
    /* enable only apply button */
    void enableApplyButton();
    /* disable only apply button */
    void disableApplyButton();
    /* enable apply button and OK button */
    void enableSaveButtons();
    /* disable apply button and OK button */
    void disableSaveButtons();
    /* set apply button and OK button state (enabled / disabled) */
    void setSaveButtonState(bool fState);
    void on_okButton_clicked();
    void on_cancelButton_clicked();
    void on_applyButton_clicked();
    void on_smartfeecheck_clicked();

    void showRestartWarning_Proxy();
    void showRestartWarning_Tor();
    void showRestartWarning_Lang();
    void showRestartWarning_URL();
    void updateDisplayUnit();
    void handleProxyIpValid(QValidatedLineEdit *object, bool fState);
    void handleTorIpValid(QValidatedLineEdit *object, bool fState);

    void on_chooseSeeder_clicked();

signals:
    void proxyIpValid(QValidatedLineEdit *object, bool fValid);
    void torIpValid(QValidatedLineEdit *object, bool fValid);

private:
    Ui::OptionsDialog *ui;
    OptionsModel *model;
    MonitoredDataMapper *mapper;
    bool fRestartWarningDisplayed_Proxy;
    bool fRestartWarningDisplayed_Tor;
    bool fRestartWarningDisplayed_Lang;
    bool fRestartWarningDisplayed_URL;
    bool fProxyIpValid;
    bool fTorIpValid;
};

#endif // OPTIONSDIALOG_H
