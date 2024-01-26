#! /bin/bash

./autogen.sh
./configure
make
./configure --enable-cli-mode
make
mv src/SorachanCoind src/soracoind
mv src/SorachanCoin_cli src/soracoin-cli
