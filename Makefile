CFLAGS=-O2 -Wall -Wno-unused-result

all: libfe448.a

.PHONY: test
test: defs.h fe448.h ge448.h sc448.h sha3.h libfe448.a
	$(CC) $(CFLAGS) -I. t/testv.c libfe448.a -o test.out
	./test.out

fe448.o: defs.h fe448.h

sc448.o: defs.h sc448.h sha3.h

ge448.o: defs.h fe448.h ge448.h sc448.h

ed448.o: defs.h fe448.h ge448.h sc448.h sha3.h

sha3.o: defs.h sha3.h

libfe448.a: fe448.o sc448.o ge448.o ed448.o sha3.o
	$(AR) rcs libfe448.a fe448.o sc448.o ge448.o ed448.o sha3.o

ge448_gen.o: defs.h fe448.h sc448.h

.PHONY: data
data: ge448_gen.o fe448.o sc448.o
	$(CC) $(CFLAGS) -o gen_data.out ge448_gen.o fe448.o sc448.o
	./gen_data.out > ge448_base.data

.PHONY: clean
clean:
	rm *.o *.out *.a
