// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/coincontroltreewidget.h>
#include <qt/coincontroldialog.h>

CoinControlTreeWidget::CoinControlTreeWidget(QWidget *parent) :
    QTreeWidget(parent)
{
}

void CoinControlTreeWidget::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Space) {     // press spacebar -> select checkbox
        event->ignore();
        int COLUMN_CHECKBOX = 0;
        if(this->currentItem()) {
            this->currentItem()->setCheckState(COLUMN_CHECKBOX, ((this->currentItem()->checkState(COLUMN_CHECKBOX) == Qt::Checked) ? Qt::Unchecked : Qt::Checked));
        }
    }
#ifdef ANDROID
    else if (event->key() == Qt::Key_Back)   // press back -> close dialog
#else
    else if (event->key() == Qt::Key_Escape) // press esc -> close dialog
#endif
    {
        event->ignore();
        CoinControlDialog *coinControlDialog = (CoinControlDialog *)this->parentWidget();
        coinControlDialog->close();
    } else {
        this->QTreeWidget::keyPressEvent(event);
    }
}
