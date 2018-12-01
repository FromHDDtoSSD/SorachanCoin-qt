#ifndef COINCONTROLTREEWIDGET_H
#define COINCONTROLTREEWIDGET_H

#include <QKeyEvent>
#include <QTreeWidget>

class CoinControlTreeWidget : public QTreeWidget
{
Q_OBJECT
private:
    CoinControlTreeWidget(const CoinControlTreeWidget &); // {}
    CoinControlTreeWidget &operator=(const CoinControlTreeWidget &); // {}
public:
    explicit CoinControlTreeWidget(QWidget *parent = 0);
    
protected:
  virtual void  keyPressEvent(QKeyEvent *event);
};

#endif // COINCONTROLTREEWIDGET_H
//@
