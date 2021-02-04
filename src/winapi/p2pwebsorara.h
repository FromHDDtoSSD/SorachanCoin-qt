// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_SORARA_H
#define SORACHANCOIN_SORARA_H

#include <winapi/common.h>
#include <QWidget>

namespace Ui {
    class SoraraWidget;
}

class SoraraWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SoraraWidget(QWidget *parent = nullptr);
    ~SoraraWidget();

public slots:
    void web(const QString &contents, bool html = false);
    void message(const QString &message, bool html = false);
    void exportClicked();

signals:
    void stopSorara();

private:
    Ui::SoraraWidget *ui;

    void startSorara();
};

/////////////////////////////////////////////////////////////////////////
// WindowsAPI macro
/////////////////////////////////////////////////////////////////////////

#define IDS_SORARA_TITLE                        L"SorachanCoin-Core SORARA"
#define IDS_SORARA_WINDOWCLASSNAME              L"prediction-system-sorara-window"
#define IDS_EDIT_MAIN                           ""
#define IDS_EDIT_MESSAGE                        ""

constexpr int SORARA_WIDTH = 800;
constexpr int SORARA_HEIGHT = 800;
constexpr int IDC_EDIT_MAIN = 3000;
constexpr int IDC_EDIT_MESSAGE = 3001;

#endif // SORACHANCOIN_SORARA_H
