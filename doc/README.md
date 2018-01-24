
Pyloncoin Core 0.14.2
=====================

Setup
---------------------
Pyloncoin Core is the original Pyloncoin client and it builds the backbone of the network. However, it downloads and stores the entire history of Pyloncoin transactions (which is currently several GBs); depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Pyloncoin Core, visit [pyloncoin.org](https://pyloncoin.org).

Running
---------------------
The following are some helpful notes on how to run Pyloncoin on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/pyloncoin-qt` (GUI) or
- `bin/pyloncoind` (headless)

### Windows

Unpack the files into a directory, and then run pyloncoin-qt.exe.

### OS X

Drag Pyloncoin-Core to your applications folder, and then run Pyloncoin-Core.

### Need Help?

* See the documentation at the [Pyloncoin Wiki](https://pyloncoin.info/)
for help and more information.
* Ask for help on [#pyloncoin](http://webchat.freenode.net?channels=pyloncoin) on Freenode. If you don't have an IRC client use [webchat here](http://webchat.freenode.net?channels=pyloncoin).
* Ask for help on the [PyloncoinTalk](https://pyloncointalk.io/) forums.

Building
---------------------
The following are developer notes on how to build Pyloncoin on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [OS X Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The Pyloncoin repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://dev.visucore.com/pyloncoin/doxygen/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Travis CI](travis-ci.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Resources
* Discuss on the [PyloncoinTalk](https://pyloncointalk.io/) forums.
* Discuss general Pyloncoin development on #pyloncoin-dev on Freenode. If you don't have an IRC client use [webchat here](http://webchat.freenode.net/?channels=pyloncoin-dev).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
