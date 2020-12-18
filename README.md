# spamprobe.py
A Bayesian spam filter in Python

requires Python 3.6+, no dependencies outside the standard library. 

download the file [spamprobe.py](https://raw.githubusercontent.com/ihaywood3/spamprobe.py/main/spamprobe.py)


can be úsed as a module, refer to functions `learn` and `probe`.
Both take a pair of dict-like objects (`words_db` and `msg_db`) which must be 
persisted by the caller. 

can also be used on the command line, run with `-h` to see options. 
