# heal-the-breach
public-domain implementation of the HTB mitigation for gzip and brotli

* To build: just `make htb`
* To install: i am already drained don't ask me

## Differences from the paper one

This one also does brotli in theory.

The code quality is not better at all. What, error checks? please no I've
had enough of C

It does not overwrite anything in the gzip, which is a very pointless
distinction and only adds six bytes of overhead by using the extra field
mechanic

the only saving grace is that the license is clear, lol. 

I hate my work

## links

https://github.com/iit-asi/PAPER-Heal-the-Breach
