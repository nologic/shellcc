GCC_BIN=`xcrun --sdk iphoneos --find gcc`
GCC=$(GCC_BASE) -arch arm64
SDK=`xcrun --sdk iphoneos --show-sdk-path`

CFLAGS = 
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks

all: shellharness

shellharness: shellharness.c
	$(GCC) -o $@ $^

shellcode: shelltest.c
	$(GCC) -o $@ $^

clean:
	rm -f *.o shellharness
