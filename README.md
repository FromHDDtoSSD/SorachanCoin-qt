
Welcome to SORA L1 Blockchain - Core [AI/Web3.0/DAOs]<br>
A hybrid scrypt PoW/PoS based cryptocurrency + AI/Web3.0/DAOs supported.

![SorachanCoin](https://raw.githubusercontent.com/FromHDDtoSSD/SorachanCoin-qt/master/src/qt/res/images/splash2.png)

What is SORA L1 L2 Blockchain?
===========================
SORA L1 Blockchain - Core wallet official sites:<br>
https://www.iuec.co.jp/<br>
https://www.junkhdd.com/<br>
https://sora.junkhdd.com/<br>
https://www.akihabara.cn/<br>
https://hk.junkhdd.com/<br>
https://de.junkhdd.com/<br>
https://id.junkhdd.com/<br>
https://us.junkhdd.com/<br>
https://au.junkhdd.com/<br>
https://testnet.junkhdd.com/

SORA L2 Blockchain - FromHDDtoSSD wallet official sites:<br>
Supported HDD/SSD/NVMe drive inspection by SORA Blockchain<br>
Supported Automatic AI Data Recovery system by SORA Blockchain<br>
https://www.iuec.co.jp/fromhddtossd2s/v3_0_dl.html<br>
https://www.iuec.co.jp/fromhddtossd2s/auto.html<br>
https://www.fromhddtossd.com/

CoinMarketCap, Coingecko:<br>
https://coinmarketcap.com/currencies/sorachancoin/<br>
https://www.coingecko.com/en/coins/sorachancoin

Bitcointalk:<br>
https://bitcointalk.org/index.php?topic=5184483

Discord, Telegram:<br>
https://discord.gg/ThMeemM<br>
https://t.me/SorachanCoin_dev_web3_chat

Twitter X:<br>
https://twitter.com/DataRescueCoin

Dev Blog:<br>
https://www.iuec.co.jp/sora/

How to use?
===========================
https://www.junkhdd.com/news/loadmap.html<br>
https://www.iuec.co.jp/fromhddtossd2s/ai_gene_to_drive.html<br>
https://www.iuec.co.jp/blockchain/web3_hd_creation.html<br>
https://www.iuec.co.jp/blockchain/i-sector.html<br>
https://www.junkhdd.com/<br>
https://www.fromhddtossd.com/

How to build?
===========================
chmod +x sora_builder.sh autogen.sh<br>
./sora_builder.sh<br>
generated under ./src, "soracoind" "soracoin-cli"

**Automatically and statically links the necessary libraries.<br>
therefore, by simply executing sora_builder.sh, <br>
"soracoind" and "soracoin-cli" will be reliably built.**

Development tools necessary for building
===========================
CentOS / AlmaLinux<br>
dnf groupinstall "Development Tools"<br>
dnf install git<br>
dnf install wget

Ubuntu / Debian<br>
sudo apt install build-essential<br>
sudo apt install git<br>
sudo apt install zlib1g-dev<br>
sudo apt install autoconf automake

Only to Debian, please execute the following command <br>
first on the working directory (SorachanCoin-qt).<br>
sed -i 's/template \<typename T=hex_vector\>/template \<typename T\>/g' src/util/strencodings.cpp

If openSUSE, please execute the following command <br>
first on the working directory (SorachanCoin-qt).<br>
chmod 777 autogen.sh<br>
sudo echo "mv ./library/libressl-2.8.2/lib64 ./library/libressl-2.8.2/lib" >> autogen.sh

soracoin-cli
===========================
e.g.<br>
soracoin-cli help<br>
soracoin-cli getinfo<br>
soracoin-cli listaccounts<br>
soracoin-cli getnewaddress ""<br>
soracoin-cli getnewethaddress ""<br>
soracoin-cli getblocktemplate '{"mode":"template"}'<br>
soracoin-cli sendfrom "user" SkNtsZ8CuYAbFKHGoNqDXvPQYF9WDa4h7W 30<br>
soracoin-cli sendethfrom "user" 0xb0e7168246ecea8c015402cf872ac28199c560f6 30<br>
soracoin-cli getkeyentangle 0xb0e7168246ecea8c015402cf872ac28199c560f6<br>
soracoin-cli gethdwalletinfo

e.g. using -datadir<br>
soracoin-cli -datadir=/coins/sora getinfo

e.g. using -testnet<br>
soracoin-cli -testnet getinfo

Block Explorer
===========================
https://us.junkhdd.com:7350/<br>
https://de.junkhdd.com:7350<br>
https://au.junkhdd.com:7350/<br>
https://id.junkhdd.com:7350/<br>
https://www.junkhdd.com:7350/<br>
https://sora.junkhdd.com:7350/
