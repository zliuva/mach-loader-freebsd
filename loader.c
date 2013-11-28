#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <libgen.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <mach-o/loader.h>

#include "osx_compat.h"

#ifdef NDEBUG
	#define LOGF(...)
#else
	#define LOGF(...) fprintf(stderr, __VA_ARGS__)
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define MAX_SEGMENTS	255
#define MAX_IMAGES		400

#define PAGE_SIZE getpagesize()

struct mach_image {
	const char *path;									// path of the image
	int fd;												// fd of the opened image

	struct mach_header_64 *header;						// reference to Mach-O header

	struct segment_command_64 *segments[MAX_SEGMENTS];	// reference to segments
	struct segment_command_64 *text_seg;				// reference to __TEXT
	int num_segments;									// number of segments

	uint64_t link_edit_base;							// offset of LINKEDIT after loading
	uint64_t slide;										// slide (if rebased)

	struct dyld_info_command *dyld_info;				// reference to LC_DYLD_INFO_ONLY

	uint64_t entry_point;								// entry point
	bool is_lc_main;									// LC_MAIN?
};

static struct mach_image *loaded_images[MAX_IMAGES];

static int num_loaded_images = 0;

static struct {
	struct mach_image *image;
	uint64_t start;
	uint64_t end;
} mapped_ranges[MAX_IMAGES * MAX_SEGMENTS];

static int num_mapped_ranges = 0;

static uint64_t highest_addr = 0; // the highest address mapped so far

extern void boot(uint64_t argc, char **argv, char **envp, char **envp_end, uint64_t entry, uint64_t is_lc_main);
extern void dyld_stub_binder(void);

static uint64_t read_uleb128(const uint8_t** p, const uint8_t* end) {
	uint64_t result = 0;
	int		 bit = 0;
	do {
		if (*p == end)
			return -1;

		uint64_t slice = **p & 0x7f;

		if (bit > 63)
			return -1;
		else {
			result |= (slice << bit);
			bit += 7;
		}
	} while (*(*p)++ & 0x80);
	return result;
}

static void add_mapped_range(struct mach_image *image, uint64_t start, uint64_t end) {
	mapped_ranges[num_mapped_ranges].image = image;
	mapped_ranges[num_mapped_ranges].start = start;
	mapped_ranges[num_mapped_ranges].end = end;

	num_mapped_ranges++;
}

static struct mach_image *find_image(uint64_t target) {
	for (int i = 0; i < num_mapped_ranges; i++) {
		if (target >= mapped_ranges[i].start && target < mapped_ranges[i].end) {
			return mapped_ranges[i].image;
		}
	}

	return NULL;
}

int load_segment(struct mach_image *image, struct segment_command_64 *seg_command) {
	LOGF("Loading segment %s: ", seg_command->segname);

	image->segments[image->num_segments++] = seg_command;

	if (strcmp(seg_command->segname, SEG_PAGEZERO) == 0) {
		assert(image->header->filetype == MH_EXECUTE); // dylib shouldn't have PAGEZERO
		LOGF("ignored.\n");
		return 0;
	}

	if (strcmp(seg_command->segname, SEG_TEXT) == 0) {
		image->text_seg = seg_command;
	}
	
	uint64_t load_addr = MAX(highest_addr, seg_command->vmaddr);

	LOGF("Mapping 0x%lx(0x%lx) to 0x%lx(0x%lx)",
			seg_command->fileoff, seg_command->filesize,
			seg_command->vmaddr, seg_command->vmsize);

	if (load_addr > seg_command->vmaddr) {
		LOGF(", rebase to 0x%lx", load_addr);

		if (image->slide) {
			assert(image->slide == load_addr - seg_command->vmaddr);
		}

		image->slide = load_addr - seg_command->vmaddr;
	}
	LOGF(": ");

	assert(VM_PROT_READ == PROT_READ);
	assert(VM_PROT_WRITE == PROT_WRITE);
	assert(VM_PROT_EXECUTE == PROT_EXEC);

	if (seg_command->initprot & PROT_READ) {
		LOGF("R");
	}
	if (seg_command->initprot & PROT_WRITE) {
		LOGF("W");
	}
	if (seg_command->initprot & PROT_EXEC) {
		LOGF("X");
	}
	LOGF("\n");

	// it seems on FreeBSD mmap aligns to page boundaries
	uint64_t aligned_size = (seg_command->filesize + PAGE_SIZE - 1) & -PAGE_SIZE;
	void *segment = mmap((void *) load_addr, aligned_size,
						 seg_command->initprot,
						 MAP_PRIVATE | MAP_FIXED,
						 image->fd, seg_command->fileoff);
	if (segment == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	assert(segment == (void *) load_addr);

	// if there's any left over, map it ourselves (it seems mmap zero-fills it too);
	if (seg_command->vmsize > aligned_size) {
		int n_zeros = seg_command->vmsize - aligned_size;
		void *zeros = mmap((void *) (load_addr + aligned_size), n_zeros,
						   seg_command->initprot,
						   MAP_ANON | MAP_PRIVATE | MAP_FIXED,
						   -1, 0);
		assert(zeros == (void *) (load_addr + aligned_size));
	}

	highest_addr = load_addr + seg_command->vmsize;

	if (strcmp(seg_command->segname, SEG_LINKEDIT) == 0) {
		image->link_edit_base = load_addr - seg_command->fileoff;
	}

	// patch syscall
	if (strcmp(seg_command->segname, SEG_TEXT) == 0) {
		mprotect(segment, seg_command->vmsize, seg_command->initprot | PROT_WRITE);

		const char * const mov_rax = "\x48\xc7\xc0";
		const char * const syscall = "\x0f\x05";
		char *text = segment;
		while (text < (char *) segment + seg_command->vmsize) {
			if (strncmp(text, mov_rax, 3) == 0 &&
				strncmp(text + 7, syscall, 2) == 0 &&
				text[6] == 0x02) {
				text[6] = 0x00;
				LOGF("Syscall %d patched\n", *((int *) (text + 3)));
				text += 9;
			}

			text++;
		}

		mprotect(segment, seg_command->vmsize, seg_command->initprot);
	}

	return 0;
}

/**
 * adapted from Apple's dyld (Apple Public Source License)
 */
const uint8_t *trie_walk(const uint8_t *start, const uint8_t *end, const char *s) {
	const uint8_t* p = start;
	while (p) {
		uint32_t terminal_size = *p++;
		if ( terminal_size > 127 ) {
			--p;
			terminal_size = read_uleb128(&p, end);
		}
		if ( (*s == '\0') && (terminal_size != 0) ) {
			return p;
		}
		const uint8_t* children = p + terminal_size;
		uint8_t children_remaining = *children++;
		p = children;
		uint32_t node_offset = 0;
		for (; children_remaining > 0; --children_remaining) {
			const char* ss = s;
			bool wrong_edge = false;
			// scan whole edge to get to next edge
			// if edge is longer than target symbol name, don't read past end of symbol name
			char c = *p;
			while ( c != '\0' ) {
				if ( !wrong_edge ) {
					if ( c != *ss )
						wrong_edge = true;
					++ss;
				}
				++p;
				c = *p;
			}
			if ( wrong_edge ) {
				// advance to next child
				++p; // skip over zero terminator
				// skip over uleb128 until last byte is found
				while ( (*p & 0x80) != 0 )
					++p;
				++p; // skil over last byte of uleb128
			}
			else {
 				// the symbol so far matches this edge (child)
				// so advance to the child's node
				++p;
				node_offset = read_uleb128(&p, end);
				s = ss;
				break;
			}
		}
		if ( node_offset != 0 )
			p = &start[node_offset];
		else
			p = NULL;
	}

	return NULL;
}

uint64_t find_exported_symbol_in_image(struct mach_image *image, const char *name) {
	const uint8_t *start = (uint8_t *) image->link_edit_base + image->dyld_info->export_off;
	const uint8_t *end = start + image->dyld_info->export_size;
	const uint8_t *node_start = trie_walk(start, end, name);

	if (node_start) {
		uint32_t flags = read_uleb128(&node_start, end);
		assert((flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_REGULAR);
		return image->slide + read_uleb128(&node_start, end);
	}

	return 0x0;
}

uint64_t find_exported_symbol(const char *name) {
	uint64_t found_addr = 0x0;
	
	for (int i = 1; i < num_loaded_images && !found_addr; i++) { // 0 is the main executable, starts from 1
		found_addr = find_exported_symbol_in_image(loaded_images[i], name);
	}

	return found_addr;
}

uint64_t do_bind(struct mach_image *image, const uint8_t * const start, const uint8_t * const end, bool lazy) {
	uint64_t seg_index = -1;
	uint64_t seg_offset = -1;
	uint64_t *vmaddr = NULL;
	void *func_ptr = NULL;
	char *symbol_name;

	const uint8_t *p = start;

	bool done = false;

	while (!done && p < end) {
		uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
		uint8_t opcode = *p & BIND_OPCODE_MASK;
		p++;

		switch (opcode) {
			case BIND_OPCODE_DONE:
				done = lazy;
				break;

			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				seg_index = immediate;
				seg_offset = read_uleb128(&p, end);
				vmaddr = (uint64_t *) (image->slide + image->segments[seg_index]->vmaddr + seg_offset);
				break;

			case BIND_OPCODE_ADD_ADDR_ULEB:
				vmaddr = (uint64_t *) ((uint64_t) vmaddr + read_uleb128(&p, end));
				break;

			case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
				symbol_name = (char *) p;
				while (*p++);
				break;

			case BIND_OPCODE_DO_BIND:
				{
#define IMPL(osx_symbol, impl) \
					if (strcmp(#osx_symbol, symbol_name) == 0) { \
						func_ptr = impl; \
					}


#ifdef USE_BSD_LIBS
					func_ptr = dlsym(RTLD_DEFAULT, symbol_name + 1); // +1 to remove the "_"

					if (!func_ptr) {
#define REPLACE(osx_symbol, bsd_symbol) \
						if (strcmp(#osx_symbol, symbol_name) == 0) { \
							func_ptr = dlsym(RTLD_DEFAULT, #bsd_symbol); \
						}

						IMPL(_compat_mode, compat_mode);

						REPLACE(___strlcpy_chk, strlcpy);
						REPLACE(___snprintf_chk, snprintf);
						REPLACE(_fstat$INODE64, fstat);
						REPLACE(_stat$INODE64, stat);
						REPLACE(_lstat$INODE64, lstat);
						REPLACE(_fts_open$INODE64, fts_open);
						REPLACE(_fts_read$INODE64, fts_read);
						REPLACE(_fts_close$INODE64, fts_close);

					}
#endif

					IMPL(dyld_stub_binder, dyld_stub_binder);

					if (!func_ptr) {
						func_ptr = (void *) find_exported_symbol(symbol_name);
					}

					if (!func_ptr) {
						LOGF("Symbol %s not found.\n", symbol_name);
						assert(NULL);
					}

					*vmaddr = (uint64_t) func_ptr;

					LOGF("%sBinding %s (seg: %lu, offset: 0x%lx)... @%p -> %p\n",
						 lazy ? "Lazy " : "",
						 symbol_name, seg_index, seg_offset, vmaddr, func_ptr);

					// advance the address, this is done so binding for the immidiate next pointer
					// in __DATA does not require another SET_SEGMENT_AND_OFFSET_ULEB
					// usually used for non-lazy binding
					vmaddr++;
				}
				break;

			default:
				break;
		}
	}

	return (uint64_t) func_ptr;
}

uint64_t dyld_stub_binder_impl(struct mach_image **image_cache, uint64_t lazy_offset) {
	struct mach_image *image = *image_cache;

	if (!image) {
		image = find_image((uint64_t) image_cache);
		*image_cache = image;

		assert(image);
	}

	const uint8_t * const start = (uint8_t *) image->link_edit_base + image->dyld_info->lazy_bind_off + lazy_offset;
	const uint8_t * const end = start + image->dyld_info->lazy_bind_size;

	return do_bind(image, start, end, true);
}

void load_mach_image(struct mach_image *image) {
	loaded_images[num_loaded_images++] = image;

	image->is_lc_main = false;
	image->num_segments = 0;
	image->slide = 0;

	image->fd = open(image->path, O_RDONLY);
	assert(image->fd >= 0);

	struct stat sb;
	fstat(image->fd, &sb);

	image->header = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, image->fd, 0);

	assert(image->header->magic == MH_MAGIC_64);
	assert(image->header->cputype == CPU_TYPE_X86_64);
	assert(image->header->filetype == MH_EXECUTE || image->header->filetype == MH_DYLIB);

	struct load_command *command = (struct load_command *) (image->header + 1);

#define IGNORE_COMMAND(command) \
		case command: \
			LOGF("Load command %d ignored: %s\n", i, #command); \
			break

	for (int i = 0; i < image->header->ncmds; i++) {
		switch (command->cmd) {
			IGNORE_COMMAND(LC_UUID);
			IGNORE_COMMAND(LC_SEGMENT);
			IGNORE_COMMAND(LC_SYMTAB);
			IGNORE_COMMAND(LC_DYSYMTAB);
			IGNORE_COMMAND(LC_THREAD);
			IGNORE_COMMAND(LC_ID_DYLIB);
			IGNORE_COMMAND(LC_PREBOUND_DYLIB);
			IGNORE_COMMAND(LC_LOAD_DYLINKER);
			IGNORE_COMMAND(LC_ID_DYLINKER);
			IGNORE_COMMAND(LC_ROUTINES);
			IGNORE_COMMAND(LC_ROUTINES_64);
			IGNORE_COMMAND(LC_TWOLEVEL_HINTS);
			IGNORE_COMMAND(LC_SUB_FRAMEWORK);
			IGNORE_COMMAND(LC_SUB_UMBRELLA);
			IGNORE_COMMAND(LC_SUB_LIBRARY);
			IGNORE_COMMAND(LC_SUB_CLIENT);
			IGNORE_COMMAND(LC_VERSION_MIN_MACOSX);
			IGNORE_COMMAND(LC_SOURCE_VERSION);
			IGNORE_COMMAND(LC_FUNCTION_STARTS);
			IGNORE_COMMAND(LC_DATA_IN_CODE);
			IGNORE_COMMAND(LC_DYLIB_CODE_SIGN_DRS);
			IGNORE_COMMAND(LC_CODE_SIGNATURE);

			case LC_SEGMENT_64:
				load_segment(image, (struct segment_command_64 *) command);
				break;

			case LC_LOAD_DYLIB:
				{
					struct dylib dylib = ((struct dylib_command *) command)->dylib;
					const char *path = (const char *) ((uint8_t *) command + dylib.name.offset);

#ifdef USE_BSD_LIBS
					// since we're using BSD libs, do not load anything starting with a '/'
					if (path[0] == '/') {
						LOGF("Skipping dylib: %s\n", path);
						break;
					}
#endif

					char buf[PATH_MAX];
					if (strncmp(path, "@executable_path", 16) == 0) {
						realpath(loaded_images[0]->path, buf);
					} else if (strncmp(path, "@loader_path", 12) == 0) {
						realpath(image->path, buf);
					}

					char resolved_path[PATH_MAX];
					sprintf(resolved_path, "%s/%s", dirname(buf), basename(path));
					

					LOGF("Loading dylib: %s\n", resolved_path);

					// we'll never have a chance to free it
					struct mach_image *dylib_image = (struct mach_image *) malloc(sizeof(struct mach_image));
					dylib_image->path = resolved_path;

					load_mach_image(dylib_image);

					LOGF("%s loaded.\n", resolved_path);
				}
				break;

			case LC_DYLD_INFO_ONLY:
				{
					image->dyld_info = (struct dyld_info_command *) command;

					const uint8_t * const start = (uint8_t *) image->link_edit_base + image->dyld_info->bind_off;
					const uint8_t * const end = start + image->dyld_info->bind_size;

					do_bind(image, start, end, false);
				}
				break;

			case LC_UNIXTHREAD:
				{
					struct x86_thread_state *thread_state;
					LOGF("Processing LC_UNIXTHREAD... ");
					thread_state = (struct x86_thread_state *) (command + 1);
					assert(thread_state->tsh.flavor == x86_THREAD_STATE64);
					image->entry_point = thread_state->uts.ts64.rip;
					LOGF("Entry Point: 0x%lx\n", image->entry_point);
				}
				break;

			case LC_MAIN:
				LOGF("Processing LC_MAIN... ");
				image->entry_point = image->text_seg->vmaddr + ((struct entry_point_command *) command)->entryoff;
				image->is_lc_main = true;
				LOGF("Entry Point: 0x%lx\n", image->entry_point);
				break;

			default:
				LOGF("Load command %d unknown: %d\n", i, command->cmd);
				break;
		}

		command = (struct load_command *) ((char *) command + command->cmdsize);
	}

	close(image->fd);

	// keep the first page for reference of header and loading commands
	munmap((uint8_t *) image->header + PAGE_SIZE, sb.st_size - PAGE_SIZE);

	// maintain a mapping between vm ranges and mach_images (implemented like Apple's dyld)
	uint64_t last_seg_start = 0, last_seg_end = 0;
	for (int i = 0; i < image->num_segments; i++) {
		if (!image->segments[i]->initprot) { // unaccessable, probably __PAGEZERO
			continue;
		}

		uint64_t seg_start = image->segments[i]->vmaddr;
		uint64_t seg_end = seg_start + image->segments[i]->vmsize;

		if (seg_start == last_seg_end) { // contiguous segments, keep counting
			last_seg_end = seg_end;
		} else {
			if (last_seg_end) {
				add_mapped_range(image, last_seg_start, last_seg_end);
			}
			
			last_seg_start = seg_start;
			last_seg_end = seg_end;
		}
	}
	
	if (last_seg_end) {
		add_mapped_range(image, last_seg_start, last_seg_end);
	}
}

int main(int argc, char **argv, char **envp) {
	struct mach_image main_image;
	main_image.path = argv[1];

	load_mach_image(&main_image);
	
	char **envp_end = envp;
	while (*envp_end) envp_end++;

	LOGF("jumping to entry point: 0x%lx\n", main_image.entry_point);
	boot(argc - 1, argv + 1, envp, envp_end, main_image.entry_point, main_image.is_lc_main);
}

