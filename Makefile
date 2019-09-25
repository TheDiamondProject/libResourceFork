# Copyright (c) 2019 Tom Hancocks
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

.PHONY: all
all: libResourceFork.a

.PHONY: clean
clean:
	- rm debug-test tests
	- rm *.a *.o
	make -C ./libEncoding clean

.PHONY: run-all-tests
run-all-tests: tests
	./tests
	
tests: libResourceFork.a
	$(CC) -o tests -I./ -DUNIT_TEST tests.c libUnit/unit.c libResourceFork.a

.PHONY: dependancies
dependancies:
	make -C ./libEncoding

libResourceFork.a: dependancies resourcefork.o
	$(AR) -r $@ resourcefork.o libEncoding/libEncoding.a

debug-test: dependancies
	$(CC) -Wall -Wpedantic -Werror -o $@ -DDEBUG_TEST -I./ resourcefork.c libEncoding/libEncoding.a
	@echo ""
	@echo "Standard ResourceFork"
	./$@ ResourceFiles/SimpleFork.rsrc
	@echo ""
	@echo "Extended ResourceFork"
	./$@ ResourceFiles/SimpleExtendedFork.rsrc

%.o: %.c
	$(CC) -Wall -Wpedantic -Werror -std=c11 -c -I./ -o $@ $^
