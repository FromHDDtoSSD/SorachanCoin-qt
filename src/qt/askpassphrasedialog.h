// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ASKPASSPHRASEDIALOG_H
#define ASKPASSPHRASEDIALOG_H

#include <QDialog>

namespace Ui {
    class AskPassphraseDialog;
}
class WalletModel;

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class AskPassphraseDialog : public QDialog
{
    Q_OBJECT
private:
    AskPassphraseDialog(const AskPassphraseDialog &)=delete;
    AskPassphraseDialog &operator=(const AskPassphraseDialog &)=delete;
    AskPassphraseDialog(AskPassphraseDialog &&)=delete;
    AskPassphraseDialog &operator=(AskPassphraseDialog &&)=delete;

public:
    enum Mode {
        Encrypt,          /**< Ask passphrase twice and encrypt */
        Unlock,           /**< Ask passphrase and unlock */
        UnlockMining,     /**< Ask passphrase and unlock for mining */
        ChangePass,       /**< Ask old passphrase + new passphrase twice */
        Decrypt           /**< Ask passphrase and decrypt wallet */
    };

    explicit AskPassphraseDialog(Mode mode, QWidget *parent = 0);
    ~AskPassphraseDialog();

    void accept();
    void setModel(WalletModel *modelIn);

private:
    Ui::AskPassphraseDialog *ui;
    Mode mode;
    WalletModel *model;
    bool fCapsLock;

private slots:
    void textChanged();
    bool event(QEvent *event);
    bool eventFilter(QObject *, QEvent *event);
};

#endif // ASKPASSPHRASEDIALOG_H
