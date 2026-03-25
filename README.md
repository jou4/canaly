# CANALY
CAN log analysis tool

# Usage
```
$ python3 dbc.py parse example/test.dbc -O example/test.json
$ cat example/canlog.txt | python3 canaly.py -a example/test.json
$ cat example/canlog.txt | python3 canaly.py -vvv example/test.json
$ cat example/canlog.txt | python3 canaly.py example/test.json Sig11 Sig12 Sig2_0_1 Sig2_0_2 Sig2_F_1 Sig2_F_2
$ cat example/canlog.txt | python3 canaly.py -v example/test.json Sig11
```
