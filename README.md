Notes
---------------------
Output can be found in log.log

Be aware in poc.cpp lines 137, 550 and 626 code has been disabled.

Configure
---------------------
 ```./configure -disable-tests -disable-bench --with-fasito --with-cvn```

Run
---------------------
 ```./src/pyloncoind -printtoconsole -datadir=$HOME/temp  -cvn=fasito  -gen=1 -cvnwaitforpeers=false -debug=cvn -paytxfee=0.2 -reindex```
