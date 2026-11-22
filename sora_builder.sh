#! /bin/bash

JOBS="1"
for OPT in "$@"
do
 case "$OPT" in
  -j*)
  JOBS="${OPT#-j}";;
 esac
done

case "$JOBS" in
  ''|*[!0-9]*|0)
    JOBS="1"
    ;;
esac

./autogen.sh -j"$JOBS"
./configure
make -j"$JOBS"
./configure --enable-cli-mode
make -j"$JOBS"
mv src/SorachanCoind src/soracoind
mv src/SorachanCoin_cli src/soracoin-cli
