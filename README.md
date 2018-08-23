Notes
---------------------


Configure
---------------------
 ```./configure -disable-tests -disable-bench --with-fasito --with-cvn```

Run
---------------------
 ```./src/pyloncoind -printtoconsole -datadir=$HOME/temp  -cvn=fasito  -gen=1 -cvnwaitforpeers=false -debug=cvn -paytxfee=0.2 -reindex```
