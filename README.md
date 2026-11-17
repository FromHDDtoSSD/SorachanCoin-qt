
Welcome to SORA Blockchain - Core, Quantum Resistance ML-DSA FIPS204 (NIST standard) supported.<br>
A hybrid scrypt PoW/PoS based cryptocurrency.

![SorachanCoin](https://raw.githubusercontent.com/FromHDDtoSSD/SorachanCoin-qt/master/src/qt/res/images/splash2.png)

What is SORA L1 L2 Blockchain?
===========================
SORA L1 Blockchain - Core wallet official sites:<br>
https://www.junkhdd.com/<br>
https://sora.junkhdd.com/<br>
https://de.junkhdd.com/<br>
https://us.junkhdd.com/

SORA L2 Blockchain - FromHDDtoSSD wallet official sites:<br>
Supported HDD/SSD/NVMe drive inspection by SORA Blockchain<br>
https://www.iuec.co.jp/fromhddtossd2s/v3_0_dl.html<br>
https://www.fromhddtossd.com/

Bitcointalk:<br>
https://bitcointalk.org/index.php?topic=5184483

Discord:<br>
https://discord.gg/ThMeemM

X:<br>
https://x.com/DataRescueCoin

How to build?
===========================
chmod +x sora_builder.sh autogen.sh<br>
./sora_builder.sh<br>
generated under ./src, "soracoind" "soracoin-cli"

Development tools necessary for building
===========================
AlmaLinux<br>
dnf groupinstall "Development Tools"<br>
dnf install git<br>
dnf install wget

Ubuntu / Debian<br>
sudo apt install build-essential<br>
sudo apt install git<br>
sudo apt install zlib1g-dev<br>
sudo apt install autoconf automake

soracoin-cli
===========================
e.g. using -datadir<br>
soracoin-cli -datadir=/coins/sora getinfo

e.g. using -testnet<br>
soracoin-cli -testnet getinfo

Block Explorer
===========================
https://us.junkhdd.com:7350/<br>
https://de.junkhdd.com:7350<br>
https://www.junkhdd.com:7350/
