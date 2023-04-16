# heal-the-breach
public-domain implementation of the HTB mitigation for gzip and brotli

* To build: just `make htb`
* To install: i am already drained don't ask me

## Differences from the paper one

* does bortli, in theory
* works on windows, in theory
* same or worse code quality
* same low amount of error checks (please stop torturing me with c, just let GPT add perror)
* does not overwrite anything in the gzip file, instead adds a field. this is very pointless
  and adds six bytes of overhead
* license is clear
* in theory you can peel off `do_htb` as a library func and skip the process overhead
* i hate my work while the paper authors are proud of it
* has a man page, can you believe it??? 

## links

https://github.com/iit-asi/PAPER-Heal-the-Breach
