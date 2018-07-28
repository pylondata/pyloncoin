# How to build a CVN
In this HOWTO we suppose that you are going to install into the folder /opt/pyloncoin. You do not need to run any step of this guide as root user except for the first two steps.
```
sudo mkdir /opt/pyloncoin
sudo chown <insertYourUserName>.<insertYourUserName> /opt/pyloncoin
```
## 1 Compile the Pyloncoin wallet
This document assumes that you have all the required development packages already installed on your system.
```
cd /opt/pyloncoin
git clone https://github.com/pyloncoin/pyloncoin.git
cd pyloncoin
./autogen.sh
./configure --disable-tests --disable-bench --with-incompatible-bdb --with-gui=qt4 --with-cvn
make -j`nproc`
```

Note: if compiling on a Raspberry PI execute a plain make else it will run out of memory:  
```
make
```

## 2 Run the Pyloncoin wallet in CVN mode
Please make sure to start your Pyloncoin wallet in normal mode first and let it download the complete block chain before restaring it as a CVN.

This is how to start the wallet software as a daemon:  
```/opt/pyloncoin/pyloncoin/src/pyloncoind -daemon ```

This is how to start the wallet software with GUI:  
```/opt/pyloncoin/pyloncoin/src/qt/pyloncoin-qt ```

There are two ways to run a CVN.  
1. By using Fasito (Pyloncoin signature token) which contains all the information required  
2. By using an x509 Key/certificate pair which containls all the information required (for testing only)  

### 3.1 Using Fasito
The Fasito is provided by the Pyloncoin development team. Once you have received the token plug it into a USB port and start the wallet using the parameters ```-cvn=fasito -gen=1 ```
### 3.2 Using an x509 Key/certificate pair
The wallet searches for a file named cvn.pem in the Pyloncoin data directory (in Linux ~/.pyloncoin2)

Start the wallet with the arguments: ```-cvn=file -gen=1 ```
