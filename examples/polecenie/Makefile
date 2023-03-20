all: test

%.o: %.c
%.o: %.s
%: %.o

test: test.c test-x64-aarch64.o
	aarch64-linux-gnu-gcc test.c test-x64-aarch64.o -no-pie -o test

test-x64.o: test-x64.c
	x86_64-linux-gnu-gcc -mcmodel=small -fno-pic -mno-red-zone -c test-x64.c -o test-x64.o

test-x64-aarch64.o: test-x64.o
	./converter test-x64.o test-x64-aarch64.o

clean:
	rm -f *.o test
