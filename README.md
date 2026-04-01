# CANALY
CAN log analysis tool

# Usage
```sh
# convert .dbc to .json ahead of time
$ python3 dbc.py parse example/test.dbc -O example/test.json

# use .json
$ cat example/canlog.txt | python3 canaly.py -a -j example/test.json

# use .dbc directly
$ cat example/canlog.txt | python3 canaly.py -a -d example/test.dbc

# options example
$ cat example/canlog.txt | python3 canaly.py -vvv -d example/test.dbc
$ cat example/canlog.txt | python3 canaly.py -j example/test.json Sig11 Sig12 Sig2_0_1 Sig2_0_2 Sig2_F_1 Sig2_F_2
$ cat example/canlog.txt | python3 canaly.py -v -d example/test.dbc Sig11
```
