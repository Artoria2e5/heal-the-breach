all: htb

test: test-gz test-br

test-gz: htb htb.c
	gzip -c < htb.c | ./htb | gzip -vd > /dev/null

test-br: htb htb.c
	brotli -c < htb.c | ./htb | brotli -vd > /dev/null
