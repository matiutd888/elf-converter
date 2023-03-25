.SECONDARY:

%.o: %.c
%.o: %.s
%: %.o

all: test-data test-multiargs test-rodata test-recurse test-data-relocation

common.o:
	aarch64-linux-gnu-gcc common.c -c -no-pie -o common.o

test-%: %-aarch64.c %-x64-aarch64.o common.o
	aarch64-linux-gnu-gcc $^ -no-pie -o $@

%-x64.o: %-x64.c
	x86_64-linux-gnu-gcc -fno-pic -mcmodel=small -fno-common -fno-stack-protector -mno-red-zone -c $<

%-x64-aarch64.o: converter %-x64.o
	./converter $(filter-out $<,$^) $@

clean:
	rm -f *.o test-*
