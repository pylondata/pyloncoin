# How to build a CVN
In this HOWTO we suppose that you are going to install into the folder /opt/faircoin. You do not need to run any step of this guide as root user except for the first two steps.
```
sudo mkdir /opt/faircoin
sudo chown <insertYourUserName>.<insertYourUserName> /opt/faircoin
```
## 1 Compile the FairCoin wallet
This document assumes that you have all the required development packages already installed on your system.
```
cd /opt/faircoin
git clone https://github.com/faircoin/faircoin.git
cd faircoin
./autogen.sh
./configure --disable-tests --disable-bench --with-incompatible-bdb --with-gui=qt4 --with-cvn
make -j`nproc`
```

Note: if compiling on a Raspberry PI execute a plain make else it will run out of memory:  
```
make
```

## 2 Run the FairCoin wallet in CVN mode
Please make sure to start your FairCoin wallet in normal mode first and let it download the complete block chain before restaring it as a CVN.

This is how to start the wallet software as a daemon:  
```/opt/faircoin/faircoin/src/faircoind -daemon ```

This is how to start the wallet software with GUI:  
```/opt/faircoin/faircoin/src/qt/faircoin-qt ```

There are two ways to run a CVN.  
1. By using Fasito (FairCoin signature token) which contains all the information required  
2. By using an x509 Key/certificate pair which containls all the information required (for testing only)  

### 3.1 Using Fasito
The Fasito is provided by the FairCoin development team. Once you have received the token plug it into a USB port and start the wallet using the parameters ```-cvn=fasito -gen=1 ```
### 3.2 Using an x509 Key/certificate pair
The wallet searches for a file named cvn.pem in the FairCoin data directory (in Linux ~/.faircoin2)

Start the wallet with the arguments: ```-cvn=file -gen=1 ```
