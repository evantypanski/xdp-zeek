CC = clang
CFLAGS = -O2 -g -Wall -target bpf
INCLUDES = -I/usr/include/bpf

XDP_PROGS = filter.o

all: $(XDP_PROGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.o

.PHONY: all clean 