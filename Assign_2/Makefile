all: logger acmonitor test_aclog akis_test


logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 


acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor


test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog


run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

# for testing 
akis_test: akis_test.c
	gcc akis_test.c -o akis_test

ARGS =

test: logger.so akis_test
	LD_PRELOAD=./logger.so ./akis_test $(ARGS)

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf akis_test

