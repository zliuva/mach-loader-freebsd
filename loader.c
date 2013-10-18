#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <mach-o/loader.h>

#ifdef NDEBUG
	#define LOGF(...)
#else
	#define LOGF(...) fprintf(stderr, __VA_ARGS__)
#endif

#define MAX_SEGMENTS 255

static int fd_image = -1;

struct segment_command_64 *segments[MAX_SEGMENTS];
struct segment_command_64 *text_seg = NULL;
static int current_seg = -1;

extern void boot(uint64_t argc, char **argv, char **envp, char **envp_end, uint64_t entry, uint64_t is_lc_main);

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

int load_segment(struct load_command *command) {
	struct segment_command_64 *seg_command = (struct segment_command_64 *) command;
	LOGF("Loading segment %s: ", seg_command->segname);

	segments[++current_seg] = seg_command;

	if (strcmp(seg_command->segname, SEG_PAGEZERO) == 0) {
		LOGF("ignored.\n");
		return 0;
	}

	if (strcmp(seg_command->segname, SEG_TEXT) == 0) {
		text_seg = seg_command;
	}

	LOGF("Mapping 0x%lx(0x%lx) to 0x%lx(0x%lx): ",
			seg_command->fileoff, seg_command->filesize,
			seg_command->vmaddr, seg_command->vmsize);

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

	void *segment = mmap((void *) seg_command->vmaddr, seg_command->vmsize,
						 seg_command->initprot,
						 MAP_PRIVATE | MAP_FIXED,
						 fd_image, seg_command->fileoff);
	if (segment == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	assert(segment == (void *) seg_command->vmaddr);

	// the loader guarantees these bytes are 0
	if (seg_command->vmsize > seg_command->filesize) {
		void *zeros = (void *) (seg_command->vmaddr + seg_command->filesize);
		int n_zeros = seg_command->vmsize - seg_command->filesize;

		mprotect(segment, seg_command->vmsize, seg_command->initprot | PROT_WRITE);
		memset(zeros, 0, n_zeros);
		mprotect(segment, seg_command->vmsize, seg_command->initprot);
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

int main(int argc, char **argv, char **envp) {
	const char *fname = argv[1];

	fd_image = open(fname, O_RDONLY);

	struct stat sb;
	fstat(fd_image, &sb);

	struct mach_header_64 *header = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd_image, 0);

	assert(header->magic == MH_MAGIC_64);
	assert(header->cputype == CPU_TYPE_X86_64);
	assert(header->filetype == MH_EXECUTE);

	struct x86_thread_state *thread_state;
	uint64_t entry_point;
	bool is_lc_main = false;

	struct load_command *command = (struct load_command *) (header + 1);

#define IGNORE_COMMAND(command) \
		case command: \
			LOGF("Load command %d ignored: %s\n", i, #command); \
			break

	for (int i = 0; i < header->ncmds; i++) {
		switch (command->cmd) {
			IGNORE_COMMAND(LC_UUID);
			IGNORE_COMMAND(LC_SEGMENT);
			IGNORE_COMMAND(LC_SYMTAB);
			IGNORE_COMMAND(LC_DYSYMTAB);
			IGNORE_COMMAND(LC_THREAD);
			IGNORE_COMMAND(LC_LOAD_DYLIB);
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
				load_segment(command);
				break;

			case LC_DYLD_INFO_ONLY:
				{
					struct dyld_info_command *info_command = (struct dyld_info_command *) command;

					uint64_t seg_index = -1;
					uint64_t seg_offset = -1;
					uint64_t *vmaddr = NULL;
					void *func_ptr = NULL;
					char *symbol_name;

					bool lazy_bind = false;
					const uint8_t * start = (uint8_t *) header + info_command->bind_off;
					const uint8_t * end = start + info_command->bind_size;
					const uint8_t *p = start;

do_bind:
					while (p < end) {
						uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
						uint8_t opcode = *p & BIND_OPCODE_MASK;
						p++;

						switch (opcode) {
							case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
								seg_index = immediate;
								seg_offset = read_uleb128(&p, end);
								vmaddr = (uint64_t *) (segments[seg_index]->vmaddr + seg_offset);
								break;

							case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
								symbol_name = (char *) p;
								while (*p++);
								break;

							case BIND_OPCODE_DO_BIND:
								func_ptr = dlsym(RTLD_DEFAULT, symbol_name + 1); // +1 to remove the "_"
								*vmaddr = (uint64_t) func_ptr;

								LOGF("Binding %s (seg: %lu, offset: 0x%lx)... @%p -> %p\n",
									 symbol_name, seg_index, seg_offset, vmaddr, func_ptr);

								// advance the address, this is done so binding for the immidiate next pointer
								// in __DATA does not require another SET_SEGMENT_AND_OFFSET_ULEB
								// usually used for non-lazy binding
								vmaddr++;
								break;

							default:
								break;
						}
					}

					if (!lazy_bind) {
						lazy_bind = true;

						start = (uint8_t *) header + info_command->lazy_bind_off;
						end = start + info_command->lazy_bind_size;
						p = start;

						goto do_bind;
					}
				}
				break;

			case LC_UNIXTHREAD:
				LOGF("Processing LC_UNIXTHREAD... ");
				thread_state = (struct x86_thread_state *) (command + 1);
				assert(thread_state->tsh.flavor == x86_THREAD_STATE64);
				entry_point = thread_state->uts.ts64.rip;
				LOGF("Entry Point: 0x%lx\n", entry_point);
				break;

			case LC_MAIN:
				LOGF("Processing LC_MAIN... ");
				entry_point = text_seg->vmaddr + ((struct entry_point_command *) command)->entryoff;
				is_lc_main = true;
				LOGF("Entry Point: 0x%lx\n", entry_point);
				break;

			default:
				LOGF("Load command %d unknown: %d\n", i, command->cmd);
				break;
		}

		command = (struct load_command *) ((char *) command + command->cmdsize);
	}
	
	close(fd_image);

	char **envp_end = envp;
	while (*envp_end) envp_end++;

	boot(argc - 1, argv + 1, envp, envp_end, entry_point, is_lc_main);
}

