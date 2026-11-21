#! /bin/bash

./autogen.sh
./configure
make

qmake SorachanCoinQ-qt.pro
make
