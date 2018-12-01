
#ifndef ABOUTDIALOG_H
#define ABOUTDIALOG_H

#include <QWidget>

namespace Ui {
    class AboutDialog;
}
class ClientModel;

//
// "About" dialog box
//
class AboutDialog : public QWidget
{
    Q_OBJECT

private:
    // AboutDialog(); Call by explicit AboutDialog(QWidget *parent = 0);
    AboutDialog(const AboutDialog &); // {}
    AboutDialog &operator=(const AboutDialog &); // {}

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
//@
