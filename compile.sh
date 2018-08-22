cd depends
make NO_QT=1
cd ..
./autogen.sh
./configure --disable-tests --disable-bench --with-fasito --with-cvn --prefix=$PWD/depends/x86_64-pc-linux-gnu
make
