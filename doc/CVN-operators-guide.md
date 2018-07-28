# CVN operators guide

This document describes the requirements for setting up and operating a CVN (cooperatively validated node) for the Pyloncoin network.

For online discussion and support please join the Pyloncoin CVN Operators telegram group here: https://telegram.me/joinchat/Bumu8gbZmAhnXoxCBr3WHg

## 1 About CVNs
The aim of a CVN is to secure the network by validating all the transactions that had been sent to the network and put them into a transaction block chain. Blocks are created every 3 minutes (180 sec.). Transactions are confirmed after they have been added to a block. A CVN is a standard Pyloncoin core client configured to use a signature token (Fasito) for continuously signing certain pieces of data of the Pyloncoin network. Every node will be assigned a unique id called the CVN ID in the form of 0x12345678.

## 2 Technical information for running a CVN

### 2.1 System requirements
A secure and stable operating system is crucial for reliably running a CVN. Therefore all requirements shown in the following list must be met by the CVN operator.

1. A Linux operating system with a current distribution is required to run a CVN. We recommend using Ubuntu or Debian. All available system updates must be applied on a regular basis.
2. The system must provide at least 1GB of free hard drive space, the more the better.
3. The Pyloncoin wallet software needs be updated as official releases are made available by the development team.
4. The system must be connected to the Internet all the time (24/7) and the TCP port 40404 must be reachable by all remote nodes from the Internet. You must not use a wireless connection as this would result in additional network latency and potential unstable internet connection.
5. The system must use a public NTP server to synchronize its system time to, e.g. pool.ntp.org to ensure that the system time is always correct. NTP means Networking Time Protocol and is intended to synchronize the system time to an accurate clock source.
6. The hardware must provide a USB 2.0 port which takes up the Fasito USB token. Please avoid using a USB-hub for the token.
7. Although not absolutely necessary, a UPS (uninterruptible power supply) would be appreciated. Note that all network related equipment should also be hooked up to the UPS to keep the network connection up in the event of a power outage.

### 2.2 Preparing your system
To build the Pyloncoin wallet software you need to install some software packages on your system. Do this by executing the following commands in a terminal:

```sudo apt-get update```  
```sudo apt-get install -y build-essential libtool autotools-dev autoconf pkg-config libssl-dev libboost-all-dev git libdb5.3-dev libdb5.3++-dev libqt4-core libqt4-gui libqt4-dev libqrencode-dev libprotobuf-dev protobuf-compiler libevent-dev```

Please note that the package names and/or versions can differ depending on your operating system. E. g. your system might provide a different version of libdb. If it doesn't find version 5.3 try version 5.1.
After package installation has completed successfully proceed by following the instructions provided here:
https://github.com/pyloncoin/pyloncoin/blob/master/doc/build-CVN.md

Make sure your Fasito is connected to your system and is working properly. You can test it by execute the following commands:
```
minicom -D /dev/ttyACM0
```

First type ```HELP``` (all upper-case!) and press enter. This will display a list of all commands.

### 2.3 The first start of your node
Create a configuration file in the data directory of Pyloncoin and copy-and-paste the following command sequence in your terminal:

```
mkdir ~/.pyloncoin2
cat > ~/.pyloncoin2/pyloncoin.conf <<EOF
# Pyloncoin CVN configuration file
logtimestamps=1
logips=1
gen=1
cvn=fasito
EOF
```

In order to connect to Fasito the wallet opens the device located here: /dev/ttyACM0. If this path is already assigned to a different device on your system you can change the default value using the following option in the config file. E.g.:
```
...
fasitodevice=/dev/ttyACM1
...
```

Now start the Pyloncoin wallet as a daemon:
```
/opt/pyloncoin/pyloncoin/src/pyloncoind -gen=0 -printtoconsole
```
The Daemon process can be stop by pressing `Ctrl-C`.

Or you can start the GUI wallet like this:
```
/opt/pyloncoin/pyloncoin/src/qt/pyloncoin-qt -gen=0
```

It will then start to download the block chain, which will take some time. The progress bar at the lower left corner of the wallet software displays the download status.
When it is finished, quit the wallet software.  

### 2.4 Normal start-up of a CVN
You can start your CVN with the following command from a terminal or by pressing Alt+F2 on your desktop:

DAEMON version:
```
/opt/pyloncoin/pyloncoin/src/pyloncoind -daemon
```

GUI version:
```
/opt/pyloncoin/pyloncoin/src/qt/pyloncoin-qt
```

Now your CVN is up and running and ready to be activated by the chain administrators.

## 3. Fees and economic model for sustainably running a CVN
In Pyloncoin transaction fees are designed to be the long term key factor for covering the costs of running a CVN and to prevent transaction SPAM. Because no new coins will be created, fees are the only reward for CVN operators.

We expect that in the short term, this will not be enough to cover electricity costs, so running a CVN can be understood as an act of solidarity. On the other hand, as the economic activity of Pyloncoin grows, the transaction activity in the blockchain will grow too, as will the income made by running a CVN, so at some point this should be enough to cover the costs of operation.

When the profit exceeds the investment, the open FairCoop assembly could decide to reduce the fees or to pool a part of the incomes for Pyloncoin development or infrastructure costs. Also, in the future we may agree on using other methodologies for avoiding spam risks and to cover the CVN expenses.

Fees are mandatory and dynamically adjustable. The effective fee per Kb is decided in the FairCoop assembly. On June 16th 2016, in a corresponding assembly (https://fair.coop/docs/minutes-of-the-10th-faircoop-open-assembly/) it has been decided to start with a fee of 0.1 PLN per 1000 bytes. This is an open process of discussion where every Pyloncoin user can be involved.

## 4. Organizational process for running a CVN

### 4.1  Socio-political criteria for running a CVN
The person responsible for certification should follow KYCVN criteria (Know your CVN). This means that online or physically, some questions should be asked to get to know the people or groups applying for certification and their real motivations.

Online information like a website, profiles in social networks like fair.coop, bitcointalk, twitter, facebook, etc. could help to confirm that information. If possible, applicants should visit a FairCoop local node nearby. This helps to get to know them better and thus ensure that they have the right intentions.
Positive criteria for CVN acceptance could be:

- Participation in the FairCoop ecosystem.
- Confirmed experience in other activities that share the FairCoop principles in general.
- Agree to values such as fairness, cooperation, circumspection, balance, patience, sharing.
- Active and visible participation in other projects connected to Pyloncoin or FairCoop.
- Availability within weeks, in emergency case within a day.
- Must have read latest version of Pyloncoin white paper (it is okay, if a CVN operator does not understand all technical details of the Pyloncoin blockchain mechanism at the beginning, but an operator should be willing to learn and share his/her experience).

### 4.2 Procedure
The certification process will be developed in a decentralized way by the various FairCoop groups.

1. One global procedure will be led by the CVN working group of the FairCoop assembly which will receive applications, support the creation of CVNs worldwide, and will present the applicants to the general FairCoop assembly. In general FairCoop assemblies will finally be decided about the approval of a CVN. Alternatively, specific assemblies could be convened for approving new CVNs to the CVN working group if there are any urgent conditions.

2. There will be regional procedures in areas where a FairCoop local node is available. FairCoop local nodes will receive the CVN applications in their area and will confirm that the goals of the applicants are aligned with proof of cooperation needs. The FairCoop local nodes should be able to make decisions about this in their open assemblies.

### 4.3 Spread of CVN certification
At least 60% of the certifications should be processed by FairCoop local nodes, and at most 40% by the global procedure. In this way, not even an attack on the global FairCoop structures would be enough to attack 50% of the network. As soon as more and more FairCoop local nodes become active, the dependence on the global procedure can be reduced. In order to have a healthy distributed procedure, a unique FairCoop local node, can't certify more than 10% of the CVN network, and the maximum number of CVNs that can be set up will be determined in the global FairCoop assemblies.

### 4.4 Transparency
The results of the certification processes will be published. So everybody can understand why an application was approved or denied.
The global CVN working group can refuse approvals for security reasons.

### 4.5 Removal of CVNs
In the event malicious behaviour of a CVN is detected, it is removed instantly by the chain administrators. Re-application of such a person to become a CVN operator is not possible in the future.
CVN operators can request removal if they are no longer willing or able to run a CVN.

The removal of a CVN will be performed by the chain administrators.

### 4.6 How to join
If you are interested in setting up a CVN, write us at cvn@pylon-network.org.

More information and discussion is available here: https://fair.coop/groups/faircoop-community/pyloncoin/pyloncoin2/
