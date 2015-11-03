GCC_BIN_OSX=`xcrun --sdk macosx --find gcc`
SDK_OSX=`xcrun --sdk macosx --show-sdk-path`
GCC_OSX=$(GCC_BASE_OSX) -arch x86_64 -fpic

GCC_BASE_OSX = $(GCC_BIN_OSX) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK_OSX) -F$(SDK_OSX)/System/Library/Frameworks -F$(SDK_OSX)/System/Library/PrivateFrameworks


GCC_BIN=`xcrun --sdk iphoneos --find gcc`
GCC=$(GCC_BASE) -arch arm64
SDK=`xcrun --sdk iphoneos --show-sdk-path`

CFLAGS = 
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks

all: shellharness

shellharness: shellharness.c
	$(GCC) -o $@ $^

shellharness64: shellharness.c
	$(GCC_OSX) -o $@ $^

clean:
	rm -f *.o shellharness
