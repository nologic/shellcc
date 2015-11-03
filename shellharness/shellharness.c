#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#ifdef __arm64
#define ASM_BREAKPOINT __asm__("BRK #3");
#elif __x86_64
#define ASM_BREAKPOINT __asm__("int3");
#elif
#error "Unsupported architecture"
#endif

typedef void (*shell)();

static void exec_buffer_bp(void* buf) {
    ASM_BREAKPOINT
    
    ((shell)buf)();
}

static void exec_buffer(void* buf) {
    ((shell)buf)();
}

int main(int argc, char* argv[]) {
	if(argc < 2) {
		return -1;
	}

	int fd = open(argv[1], O_RDONLY);

	if(fd < 0) {
        perror("get_file_data failed");

        return -2;
    }

    int filesize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, 0);

	void* shellcode = mmap(0, filesize, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if(shellcode == MAP_FAILED) {
        perror("Unable to map mach-o for reading");
        
        return -3;
    }

    if(argc > 2) {
        exec_buffer_bp(shellcode);
    } else {
        exec_buffer(shellcode);
    }

	return 0;
}
