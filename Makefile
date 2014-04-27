LIBRHASH_DIR=/home/savrus/usr/src/rhash-1.2.10/librhash

all: horriblecheck

horriblecheck: horriblecheck.c
	 gcc -I${LIBRHASH_DIR}  -Wall -o horriblecheck horriblecheck.c ${LIBRHASH_DIR}/librhash.a

clean:
	rm horriblecheck
