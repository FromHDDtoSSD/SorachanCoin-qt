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
qmake SorachanCoinQ-qt.pro
make -j"$JOBS"
