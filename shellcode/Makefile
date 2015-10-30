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

connectout: connectout.c
	$(GCC) -o $@ $^
	otool -t -v $@
	python extractshell.py -o $@ -s $@.b
	hexdump -C $@.b

clean:
	rm -f *.o shelltest shelltest.b connectout connectout.b
