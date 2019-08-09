.PHONY: all
all: libResourceFork.a

.PHONY: clean
clean:
	rm *.a *.o
	make -C ./libEncoding clean

.PHONY: dependancies
dependancies:
	make -C ./libEncoding

libResourceFork.a: dependancies resourcefork.o
	$(AR) -r $@ resourcefork.o libEncoding/libEncoding.a

%.o: %.c
	$(CC) -c -o $@ $^
