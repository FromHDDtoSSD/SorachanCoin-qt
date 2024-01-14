#! /bin/bash

./autogen.sh
./configure
make
./configure --enable-cli-mode
make
mv src/SorachanCoin_cli src/SorachanCoin-cli
