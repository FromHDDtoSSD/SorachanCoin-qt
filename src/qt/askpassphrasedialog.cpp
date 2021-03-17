// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/askpassphrasedialog.h>
#include <ui_askpassphrasedialog.h>
#include <wallet.h>
#include <qt/guiconstants.h>
#include <qt/dialogwindowflags.h>
#include <qt/walletmodel.h>
#include <QMessageBox>
#include <QPushButton>
#include <QKeyEvent>
#include <allocator/qtsecure.h>

AskPassphraseDialog::AskPassphraseDialog(Mode mode, QWidget *parent) :
    QDialog(parent, DIALOGWINDOWHINTS),
    ui(new(std::nothrow) Ui::AskPassphraseDialog),
    mode(mode),
    model(0),
    fCapsLock(false)
{
    if(! ui) throw qt_error("AskPassphraseDialog: out of memory.", this);

    ui->setupUi(this);
    ui->passEdit1->setMaxLength(MAX_PASSPHRASE_SIZE);
    ui->passEdit2->setMaxLength(MAX_PASSPHRASE_SIZE);
    ui->passEdit3->setMaxLength(MAX_PASSPHRASE_SIZE);

    // Setup Caps Lock detection.
    ui->passEdit1->installEventFilter(this);
    ui->passEdit2->installEventFilter(this);
    ui->passEdit3->installEventFilter(this);

    switch(mode)
    {
        case Encrypt: // Ask passphrase x2
            ui->passLabel1->hide();
            ui->passEdit1->hide();
            ui->warningLabel->setText(tr("Enter the new passphrase to the wallet.<br/>Please use a passphrase of <b>10 or more random characters</b>, or <b>eight or more words</b>."));
            setWindowTitle(tr("Encrypt wallet"));
            break;
        case Unlock: // Ask passphrase
        case UnlockMining:
            ui->warningLabel->setText(tr("This operation needs your wallet passphrase to unlock the wallet."));
            ui->passLabel2->hide();
            ui->passEdit2->hide();
            ui->passLabel3->hide();
            ui->passEdit3->hide();
            setWindowTitle(tr("Unlock wallet"));
            break;
        case Decrypt:   // Ask passphrase
            ui->warningLabel->setText(tr("This operation needs your wallet passphrase to decrypt the wallet."));
            ui->passLabel2->hide();
            ui->passEdit2->hide();
            ui->passLabel3->hide();
            ui->passEdit3->hide();
            setWindowTitle(tr("Decrypt wallet"));
            break;
        case ChangePass: // Ask old passphrase + new passphrase x2
            setWindowTitle(tr("Change passphrase"));
            ui->warningLabel->setText(tr("Enter the old and new passphrase to the wallet."));
            break;
    }

    textChanged();
    connect(ui->passEdit1, SIGNAL(textChanged(QString)), this, SLOT(textChanged()));
    connect(ui->passEdit2, SIGNAL(textChanged(QString)), this, SLOT(textChanged()));
    connect(ui->passEdit3, SIGNAL(textChanged(QString)), this, SLOT(textChanged()));
}

AskPassphraseDialog::~AskPassphraseDialog() {
    // Attempt to overwrite text so that they do not linger around in memory
    ui->passEdit1->setText(QString(" ").repeated(ui->passEdit1->text().size()));
    ui->passEdit2->setText(QString(" ").repeated(ui->passEdit2->text().size()));
    ui->passEdit3->setText(QString(" ").repeated(ui->passEdit3->text().size()));
    delete ui;
}

void AskPassphraseDialog::setModel(WalletModel *modelIn) {
    model = modelIn;
}

void AskPassphraseDialog::accept() {
    SecureString oldpass, newpass1, newpass2;
    if(! model) return;

    oldpass.reserve(MAX_PASSPHRASE_SIZE);
    newpass1.reserve(MAX_PASSPHRASE_SIZE);
    newpass2.reserve(MAX_PASSPHRASE_SIZE);

    // SorachanCoin: SecureString operator () (SecureAllocator and OpenSSL_cleanse)
    oldpass(ui->passEdit1->text().toStdString(), const_cast<ushort *>(ui->passEdit1->text().utf16()));
    newpass1(ui->passEdit2->text().toStdString(), const_cast<ushort *>(ui->passEdit2->text().utf16()));
    newpass2(ui->passEdit3->text().toStdString(), const_cast<ushort *>(ui->passEdit3->text().utf16()));

    // SorachanCoin SecureString check OK.
    assert(*ui->passEdit1->text().toStdString().c_str()=='\0');
    assert(*ui->passEdit2->text().toStdString().c_str()=='\0');
    assert(*ui->passEdit3->text().toStdString().c_str()=='\0');

    ui->passEdit1->setText(QString(""));
    ui->passEdit2->setText(QString(""));
    ui->passEdit3->setText(QString(""));

    switch(mode)
    {
    case Encrypt:
        {

        if(newpass1.empty() || newpass2.empty()) {
            // Cannot encrypt with empty passphrase
            break;
        }

        QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm wallet encryption"),
                 tr("Warning: If you encrypt your wallet and lose your passphrase, you will <b>LOSE ALL OF YOUR COINS</b>!") + "<br><br>" + tr("Are you sure you wish to encrypt your wallet?"),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
        if(retval == QMessageBox::Yes) {
            if(newpass1 == newpass2) {
                if(model->setWalletEncrypted(true, newpass1)) {
#ifdef WALLET_SQL_MODE
                    QMessageBox::information(this, tr("Wallet encrypted"), tr("Wallet encryption succeeded."));
#else
                    QMessageBox::warning(this, tr("Wallet encrypted"),
                                         "<qt>" + 
                                         tr("SorachanCoin will close now to finish the encryption process. "
                                         "Remember that encrypting your wallet cannot fully protect "
                                         "your coins from being stolen by malware infecting your computer.") + 
                                         "<br><br><b>" + 
                                         tr("IMPORTANT: Any previous backups you have made of your wallet file "
                                         "should be replaced with the newly generated, encrypted wallet file. "
                                         "For security reasons, previous backups of the unencrypted wallet file "
                                         "will become useless as soon as you start using the new, encrypted wallet.") + 
                                         "</b></qt>");
                    QApplication::quit();
#endif
                } else {
                    QMessageBox::critical(this, tr("Wallet encryption failed"),
                                         tr("Wallet encryption failed due to an internal error. Your wallet was not encrypted."));
                }
                QDialog::accept(); // Success
            } else {
                QMessageBox::critical(this, tr("Wallet encryption failed"),
                                     tr("The supplied passphrases do not match."));
            }
        } else {
            QDialog::reject(); // Cancelled
        }

        }
        break;
    case Unlock:
        if(! model->setWalletLocked(false, oldpass)) {
            QMessageBox::critical(this, tr("Wallet unlock failed"),
                                  tr("The passphrase entered for the wallet decryption was incorrect."));
        } else {
            QDialog::accept(); // Success
        }
        break;
    case UnlockMining:
        if(! model->setWalletLocked(false, oldpass)) {
            QMessageBox::critical(this, tr("Wallet unlock failed"),
                                  tr("The passphrase entered for the wallet decryption was incorrect."));
        } else {
            QDialog::accept(); // Success
            CWallet::fWalletUnlockMintOnly = true;
        }
        break;
    case Decrypt:
        if(! model->setWalletEncrypted(false, oldpass)) {
            QMessageBox::critical(this, tr("Wallet decryption failed"),
                                  tr("The passphrase entered for the wallet decryption was incorrect."));
        } else {
#ifdef WALLET_SQL_MODE
            QMessageBox::information(this, tr("Wallet decrypted"), tr("Wallet decrypted succeeded."));
            QDialog::accept();
#else
            QMessageBox::warning(this, tr("Wallet decrypted"),
                                     "<qt>" + 
                                     tr("SorachanCoin will close now to finish the decryption process. ") +
                                     "</b></qt>");
            QApplication::quit();
#endif
        }
        break;
    case ChangePass:
        if(newpass1 == newpass2) {
            if(model->changePassphrase(oldpass, newpass1)) {
                QMessageBox::information(this, tr("Wallet encrypted"),
                                     tr("Wallet passphrase was successfully changed."));
                QDialog::accept(); // Success
            } else {
                QMessageBox::critical(this, tr("Wallet encryption failed"),
                                     tr("The passphrase entered for the wallet decryption was incorrect."));
            }
        } else {
            QMessageBox::critical(this, tr("Wallet encryption failed"),
                                 tr("The supplied passphrases do not match."));
        }
        break;
    }
}

void AskPassphraseDialog::textChanged() {
    // Validate input, set Ok button to enabled when acceptable
    bool acceptable = false;
    switch(mode)
    {
    case Encrypt: // New passphrase x2
        acceptable = !ui->passEdit2->text().isEmpty() && !ui->passEdit3->text().isEmpty();
        break;
    case Unlock: // Old passphrase x1
    case UnlockMining:
    case Decrypt:
        acceptable = !ui->passEdit1->text().isEmpty();
        break;
    case ChangePass: // Old passphrase x1, new passphrase x2
        acceptable = !ui->passEdit1->text().isEmpty() && !ui->passEdit2->text().isEmpty() && !ui->passEdit3->text().isEmpty();
        break;
    }
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(acceptable);
}

bool AskPassphraseDialog::event(QEvent *event) {
    // Detect Caps Lock key press.
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_CapsLock) {
            fCapsLock = !fCapsLock;
        }
        if (fCapsLock) {
            ui->capsLabel->setText(tr("Warning: The Caps Lock key is on!"));
        } else {
            ui->capsLabel->clear();
        }
    }
    return QWidget::event(event);
}

bool AskPassphraseDialog::eventFilter(QObject *object, QEvent *event) {
    /* Detect Caps Lock.
     * There is no good OS-independent way to check a key state in Qt, but we
     * can detect Caps Lock by checking for the following condition:
     * Shift key is down and the result is a lower case character, or
     * Shift key is not down and the result is an upper case character.
     */
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        QString str = ke->text();
        if (str.length() != 0) {
            const QChar *psz = str.unicode();
            bool fShift = (ke->modifiers() & Qt::ShiftModifier) != 0;
            if ((fShift && psz->isLower()) || (!fShift && psz->isUpper())) {
                fCapsLock = true;
                ui->capsLabel->setText(tr("Warning: The Caps Lock key is on!"));
            } else if (psz->isLetter()) {
                fCapsLock = false;
                ui->capsLabel->clear();
            }
        }
    }
    return QDialog::eventFilter(object, event);
}
