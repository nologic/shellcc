GCC_BIN_OSX=`xcrun --sdk macosx --find gcc`
SDK_OSX=`xcrun --sdk macosx --show-sdk-path`
GCC_OSX=$(GCC_BASE_OSX) -arch x86_64 -fpic

GCC_BASE_OSX = $(GCC_BIN_OSX) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK_OSX) -F$(SDK_OSX)/System/Library/Frameworks -F$(SDK_OSX)/System/Library/PrivateFrameworks

GCC_BIN=`xcrun --sdk iphoneos --find gcc`
GCC=$(GCC_BASE) -arch arm64
SDK=`xcrun --sdk iphoneos --show-sdk-path`

CFLAGS = -fno-stack-protector -fomit-frame-pointer -fno-exceptions
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks

all: shelltest

shelltest: shelltest.c
	$(GCC) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

shelltest64: shelltest.c
	$(GCC) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

connectout: connectout.c
	$(GCC) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

connectout64: connectout.c
	$(GCC_OSX) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

injectdyld64: injectdyld.c
	$(GCC_OSX) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

injectdyld: injectdyld.c
	$(GCC) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

injectdyld_file64: injectdyld_file.c
	$(GCC_OSX) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

clean:
	rm -f *.o shelltest shelltest.b connectout connectout.b connectout64.b connectout64 injectdyld64 injectdyld64.b
