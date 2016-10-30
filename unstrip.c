/*
 * Decrypt the loaded binary,
 * Reconstruct the symbol table from the ObjectiveC runtime data,
 * Patch the arch-specific object.
 *
 * Usage: ./unstrip MyApp
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>

/* Helpers */

#define error_out(...) \
	do { \
		fprintf(stderr, __VA_ARGS__); \
		goto out; \
	} while(0)

#define verbose(...) \
	do { \
		if (args.verbose) { \
			fprintf(stdout, __VA_ARGS__); \
		} \
	} while(0)

/* Mach-o parsing */

const char *macho_current_arch()
{
	const struct mach_header *mh;
	const NXArchInfo *info;

	mh = (struct mach_header*)_dyld_get_image_header(0);
	info = NXGetArchInfoFromCpuType(mh->cputype, mh->cpusubtype);

	return info->name;
}

struct fat_arch *macho_fat_arch(void *data, const char *arch_name)
{
	const NXArchInfo *info;
	const struct fat_header *fh = data;
	struct fat_arch *arch = NULL;
	struct fat_arch *curarch;

	info = NXGetArchInfoFromName(arch_name);
	if (!info) {
		goto out;
	}

	if (fh->magic != FAT_CIGAM) {
		goto out;
	}

	curarch = (struct fat_arch*)(fh+1);
	for (int i = 0; i < __builtin_bswap32(fh->nfat_arch); i++, curarch++) {
		if (__builtin_bswap32(curarch->cputype) == info->cputype) {
			if ((info->cpusubtype & ~CPU_SUBTYPE_MASK) == 0) {
				/* Generic arch, taking the first subtype */
				arch = curarch;
				break;
			}
			if ((__builtin_bswap32(curarch->cpusubtype) & ~CPU_SUBTYPE_MASK)	
		        == (info->cpusubtype & ~CPU_SUBTYPE_MASK)) {
				arch = curarch;
				break;
			}
		}
	}

out:
	return arch;
}

const struct mach_header *macho_header_for_arch(void *data, const char *arch_name)
{
	const NXArchInfo *info;
	const struct fat_arch *arch;
	const struct mach_header *mh = NULL;

	info = NXGetArchInfoFromName(arch_name);
	if (!info) {
		error_out("Unknown arch %s\n", arch_name);
	}

	arch = macho_fat_arch(data, arch_name);
	if (arch) {
		mh = (struct mach_header*)
			((uint64_t)data+ __builtin_bswap32(arch->offset));
	}
	else {
		const struct mach_header *curmh = data;

		if (curmh->magic == MH_MAGIC || curmh->magic == MH_MAGIC_64) {
			if (curmh->cputype == info->cputype) {
				if (((info->cpusubtype & ~CPU_SUBTYPE_MASK) == 0) ||
			        ((info->cpusubtype & ~CPU_SUBTYPE_MASK) ==
			         (curmh->cpusubtype & ~CPU_SUBTYPE_MASK))) {
					mh = curmh;
				}
			}
		}
	}

out:
	return mh;
}

uint32_t macho_align(void *data, const char *arch_name)
{
	uint32_t align = 0;
	const struct fat_arch *arch;

	arch = macho_fat_arch(data, arch_name);
	if (arch) {
		align = __builtin_bswap32(arch->align);
	}

	return align;
}


int macho_is_64(const struct mach_header *mh)
{
	return mh->magic == MH_MAGIC_64;
}

void *macho_get_load_command(const struct mach_header *mh, uint32_t cmd)
{
	struct load_command *load_command;
	void *match = NULL;

	if (macho_is_64(mh)) {
		load_command = (struct load_command*)((struct mach_header_64*)mh+1);
	}
	else {
		load_command = (struct load_command*)((struct mach_header*)mh+1);
	}

	for (int i = 0; i < mh->ncmds; i++) {
		if (load_command->cmd == cmd) {
			match = load_command;
			break;
		}

		load_command = (struct load_command*)
			((uint64_t)load_command+load_command->cmdsize);
	}

	return match;
}

int macho_section_info(
	const struct mach_header *mh, const char *segname, const char *secname,
	uint64_t *address, uint64_t *offset, uint64_t *size)
{
	int err = -1;

	if (macho_is_64(mh)) {
		const struct section_64 *sect;
		sect = getsectbynamefromheader_64((struct mach_header_64*)mh, segname, secname);
		if (!sect) {
			goto out;
		}
		if (address) {
			*address = sect->addr;
		}
		if (offset) {
			*offset = sect->offset;
		}
		if (size) {
			*size = sect->size;
		}
	}
	else {
		const struct section *sect;
		sect = getsectbynamefromheader(mh, segname, secname);
		if (!sect) {
			goto out;
		}
		if (address) {
			*address = sect->addr;
		}
		if (offset) {
			*offset = sect->offset;
		}
		if (size) {
			*size = sect->size;
		}
	}

	err = 0;

out:
	return err;
}

int macho_add_symbol(
	const struct mach_header *mh,
	struct nlist **symtab, size_t *symtab_size,
	char **strtab, size_t *strtab_size,
	const char *name, uint64_t address)
{
	int err = -1;
	struct symtab_command *symtab_lc;
	char *curstr;
	size_t nlist_size;

	nlist_size = macho_is_64(mh) ? sizeof(struct nlist_64): sizeof(struct nlist);

	/* Get strtab offset */
	symtab_lc = macho_get_load_command(mh, LC_SYMTAB);
	if (!symtab_lc) {
		error_out("Image has no symbole table\n");
	}

	/* Create new symbol */
	*symtab = realloc(*symtab, *symtab_size + nlist_size);

	if (macho_is_64(mh)) {
		struct nlist_64 *cursym = (struct nlist_64*)
			((uint64_t)*symtab + *symtab_size);
		cursym->n_type = N_SECT;
		cursym->n_sect = 1;
		cursym->n_desc = address & 1 ? N_ARM_THUMB_DEF : 0;
		cursym->n_un.n_strx = symtab_lc->strsize + *strtab_size - 1;
		cursym->n_value = address & ~1UL; /* Clear Thumb */
	}
	else {
		struct nlist *cursym = (struct nlist*)
			((uint64_t)*symtab + *symtab_size);
		cursym->n_type = N_SECT;
		cursym->n_sect = 1;
		cursym->n_desc = address & 1 ? N_ARM_THUMB_DEF : 0;
		cursym->n_un.n_strx = symtab_lc->strsize + *strtab_size - 1;
		cursym->n_value = address & ~1UL; /* Clear Thumb */
	}

	*symtab_size += nlist_size;

	/* Copy symbol name */
	*strtab = realloc(*strtab, *strtab_size + strlen(name) + 1);
	curstr = (char*)((uint64_t)*strtab + *strtab_size);

	strcpy(curstr, name);
	*strtab_size += strlen(name) + 1;

	err = 0;

out:
	return err;
}

/* File helpers */

char *create_patched_name(const char *app_name)
{
	char *patched_name;
	const char *app_basename;
	const char suffix[] = ".patched";

	app_basename = strrchr(app_name, '/');
	if (!app_basename) {
		app_basename = app_name;
	}
	else {
		app_basename += 1;
	}

	patched_name = malloc(strlen(app_basename)+sizeof(suffix)+1);
	strcpy(patched_name, app_basename);
	strcat(patched_name+strlen(app_basename), suffix);

	return patched_name;
}

int map_file(int fd, void **map, size_t *size)
{
	int err = -1;
	struct stat stat;

	err = fstat(fd, &stat);
	if (err < 0) {
		goto out;
	}

	*map = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		map = NULL;
		goto out;
	}

	*size = stat.st_size;
	err = 0;

out:
	return err;
}

int extract_slice(const char *slice_fn, const void *mh, size_t size)
{
	int err = -1;
	int slice_fd = -1;

	slice_fd = open(slice_fn, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (slice_fd < 0) {
		error_out("%s\n", strerror(errno));
	}

	err = write(slice_fd, mh, size);
	if (err < 0) {
		error_out("%s\n", strerror(errno));
	}

	err = 0;

out:
	if (slice_fd >= 0) {
		close(slice_fd);
	}

	return err;
}

#define _POSIX_SPAWN_DISABLE_ASLR 0x0100


extern kern_return_t mach_vm_region(
      vm_map_t map, 
      mach_vm_address_t *address,
      mach_vm_size_t *size,
      vm_region_flavor_t flavor,
      vm_region_info_t info,
      mach_msg_type_number_t *count,
      mach_port_t *object_name
);
int dump_decrypted(int *buffer, const char *fn, const char *arch, size_t off, size_t size)
{
	int err = -1;
	pid_t child = 0;
	mach_port_t task;
    posix_spawnattr_t attr;
    const struct mach_header mh;
	const NXArchInfo *arch_info;
	vm_size_t read;
	kern_return_t ret;
	uint64_t mh_offset = 0x1000;
	uint64_t aslr_offset = 0x1000;

	mach_vm_address_t vmaddr = 0;
	mach_vm_size_t vmsize;
	vm_region_basic_info_data_64_t info;
	mach_msg_type_number_t info_count = sizeof(info);
	memory_object_name_t object;

    /* Spawn the app - suspend on exec */
    posix_spawnattr_init(&attr);
    ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    if (ret) {
		error_out("Can't set spawn attributes\n");
    }

    ret = posix_spawn(&child, fn, 0, &attr, NULL, NULL);
    if (ret) {
		error_out("Spawn failed\n");
    }

    posix_spawnattr_destroy(&attr);

	ret = task_for_pid(mach_task_self(), child, &task);
	if (ret != KERN_SUCCESS) {
		error_out("Can't get mach task - %d\n", ret);
	}

	/* Find ASLR offset */
	do {
		ret = mach_vm_region(
			task, &vmaddr, &vmsize, VM_REGION_BASIC_INFO_64,
			(vm_region_info_t)&info, &info_count, &object);

		if (vmsize == size) {
			/* Looks like __text */
			aslr_offset = vmaddr - (mh_offset + off);
			break;
		}

		vmaddr += vmsize;

	} while (ret == KERN_SUCCESS);

	if (ret != KERN_SUCCESS) {
		error_out("Can't find ASLR offset - %d\n", ret);
	}

	/* Check arch of the loaded image */
	ret = vm_read_overwrite(
		task, aslr_offset + mh_offset, sizeof(mh), (pointer_t)&mh, &read);
	if (ret != KERN_SUCCESS) {
		error_out("Can't read vmem - %d\n", ret);
	}

	arch_info = NXGetArchInfoFromName(arch);
	if ((arch_info->cputype != mh.cputype) ||
	    ((arch_info->cpusubtype != 0) &&
	     (arch_info->cpusubtype != mh.cpusubtype))) {
		error_out("Exec launched %s slice (instead of %s) - use a thin binary\n",
			NXGetArchInfoFromCpuType(mh.cputype, mh.cpusubtype)->name, arch);
	}

	/* Copy decrypted data from child memory into buffer */
	ret = vm_read_overwrite(
		task, aslr_offset + mh_offset + off, size, (pointer_t)buffer, &read);
	if (ret != KERN_SUCCESS) {
		error_out("Can't read vmem - %d\n", ret);
	}

	err = 0;

out:
	if (child > 0) {
		kill(child, SIGKILL);
	}

	return err;
}

/* ObjectiveC runtime structs (from runtime/objc-runtime-new.h) */

struct method_t {
	uint32_t name;
	uint32_t types;
	uint32_t imp;
};

struct method_64_t {
	uint64_t name;
	uint64_t types;
	uint64_t imp;
};

struct method_list_t {
	uint32_t entsize_NEVER_USE;
	uint32_t count;
};

struct class_ro_t {
	uint32_t flags;
	uint32_t instanceStart;
	uint32_t instanceSize;
	uint32_t ivarLayout;
	uint32_t name;
	uint32_t baseMethods;
	uint32_t baseProtocols;
	uint32_t ivars;
	uint32_t weakIvarLayout;
	uint32_t baseProperties;
};

struct class_ro_64_t {
	uint32_t flags;
	uint32_t instanceStart;
	uint32_t instanceSize;
	uint32_t reserved;
	uint64_t ivarLayout;
	uint64_t name;
	uint64_t baseMethods;
	uint64_t baseProtocols;
	uint64_t ivars;
	uint64_t weakIvarLayout;
	uint64_t baseProperties;
};

struct class_t {
	uint32_t isa;
	uint32_t superclass;
	uint32_t cache;
	uint32_t vtable;
	uint32_t data;
};

struct class_64_t {
	uint64_t isa;
	uint64_t superclass;
	uint64_t cache;
	uint64_t vtable;
	uint64_t data;
};

/* ObjectiveC runtime parser */

int create_symtab_from_classlist(
	const struct mach_header *mh, uint8_t *__text_data, uint64_t __text_addr,
	struct nlist **symtab, size_t *symtab_size, char **strtab, size_t *strtab_size)
{
	int err = -1;
	uint64_t classlist;
	uint64_t objc_address;
	uint64_t objc_offset;
	uint64_t objc_size;
	uint64_t data_offset;
	uint64_t text_offset;
	size_t ptr_size;
	char *name = NULL;
	int i;

	/* Make room for new symbols and strings */ 
	*symtab = NULL;
	*symtab_size = 0;

	*strtab = NULL;
	*strtab_size = 0;

	/* Get classlist section and compute offsets */
	err = macho_section_info(
		mh, "__DATA", "__objc_classlist",
		&objc_address, &objc_offset, &objc_size);
	if (err) {
		/* No objc symbols - ignoring */
		err = 0;
		goto out;
	}

	ptr_size = macho_is_64(mh) ? 8 : 4;

	classlist = (uint64_t)mh + objc_offset;

	data_offset = (uint64_t)mh + objc_offset - objc_address;
	text_offset = (uint64_t)__text_data - __text_addr;

	/* Loop through all the defined classes */
	for (i = 0; i < objc_size / ptr_size; i++) {
		uint64_t baseMethods;
		const char *class_name;
		uint64_t metaclass;
		bool is_meta = false;

		/* ObjC data lives in __DATA */
		/* Strings live in __TEXT */

		uint64_t isa_addr = *(uint64_t*)(classlist + ptr_size * i) + data_offset;

parse_class:
		if (macho_is_64(mh)) {
			struct class_64_t *cls = (struct class_64_t*)isa_addr;
			struct class_ro_64_t *cls_ro =
				(struct class_ro_64_t*)(cls->data + data_offset);
			class_name = (char*)(cls_ro->name + text_offset);
			baseMethods = cls_ro->baseMethods;
			metaclass = cls->isa;
		}
		else {
			struct class_t *cls = (struct class_t*)isa_addr;
			struct class_ro_t *cls_ro =
				(struct class_ro_t*)(cls->data + data_offset);
			class_name = (char*)(cls_ro->name + text_offset);
			baseMethods = cls_ro->baseMethods;
			metaclass = cls->isa;
		}

		if (baseMethods) {
			struct method_list_t *methods;
			uint64_t method_ptr;
			int m;

			methods = (struct method_list_t*)(baseMethods + data_offset);
			method_ptr = (uint64_t)(methods + 1);

			/* For all methods */
			for (m = 0; m < methods->count; m++) {
				const char *method_name;
				uint64_t impl;
				int name_len;
				char *curchar;


				if (macho_is_64(mh)) {
					struct method_64_t *method = (struct method_64_t*)method_ptr;
					method_ptr += sizeof(struct method_64_t);

					method_name = (char *)(method->name + text_offset);
					impl = method->imp;
				}
				else {
					struct method_t *method = (struct method_t*)method_ptr;
					method_ptr += sizeof(struct method_t);

					method_name = (char *)(method->name + text_offset);
					impl = method->imp;
				}

				/* Create symbol name */
				name_len = 2 + strlen(class_name) + 1 + strlen(method_name) + 2;
				name = malloc(name_len);
				curchar = name;

				*curchar++ = is_meta ? '+' : '-';
				*curchar++ = '[';
				strcpy(curchar, class_name);
				curchar += strlen(class_name);
				*curchar++ = ' ';
				strcpy(curchar, method_name);
				curchar += strlen(method_name);
				*curchar++ = ']';
				*curchar++ = '\0';

				err = macho_add_symbol(
					mh,
					symtab, symtab_size,
					strtab, strtab_size,
					name, impl);
				if (err) {
					goto out;
				}
			}

			/* TODO: Get protocol methods */
			/* TODO: Get category methods */
		}

		if (!is_meta) {
			is_meta = true;
			isa_addr = metaclass + data_offset;
			goto parse_class;
		}
	}

	err = 0;

out:
	if (name) {
		free(name);
	}

	return err;
}

/* Options parsing */

struct args {
	int verbose;
	int no_objc;
	int decrypt;
	const char *arch;
	const char *filename;
	
	struct symbol_option {
		char *name;
		uint64_t address;
	} *symbols;
	int nsymbols;
};

int parse_symbol_options(struct args *args, const char *optarg)
{
	int err = -1;
	char *symstr;
	struct symbol_option *symbol;
	char *name;
	char *addstr;

	symstr = malloc(strlen(optarg)+1);
	strcpy(symstr, optarg);
	name = strtok(symstr, "=");
	addstr = strtok(NULL, "=");
	
	if (!addstr || strtok(NULL, "=")) {
		goto out;
	}

	args->symbols = realloc(args->symbols,
		(args->nsymbols+1) * sizeof(struct symbol_option));
	if (!args->symbols) {
		goto out;
	}

	symbol = args->symbols + args->nsymbols;

	symbol->name = name;
	symbol->address = strtoll(addstr, NULL, 0);
	args->nsymbols++;

	err = 0;

out:
	return err;
}

int parse_options(struct args *args, int argc, char * const *argv)
{
	int err = -1;
	char ch;

	static struct option options[] = {
		{ "arch", required_argument, NULL, 'a' },
		{ "no-objc", no_argument, NULL, 'n' },
		{ "decrypt", no_argument, NULL, 'd' },
		{ "symbol", required_argument, NULL, 's' },
		{ "verbose", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	bzero(args, sizeof(*args));

	while ((ch = getopt_long(argc, argv, "a:s:vnd", options, NULL)) != -1) {
		switch (ch) {
			case 'a':
				args->arch = optarg;
				break;
			case 'v':
				args->verbose = 1;
				break;
			case 'n':
				args->no_objc = 1;
				break;
			case 'd':
				args->decrypt = 1;
				break;
			case 's':
				err = parse_symbol_options(args, optarg);
				if (err) {
					goto out;
				}
				break;
			case 0:
				break;
			default:
				goto out;
		}
	}

	if (optind + 1 != argc) {
		goto out;
	}

	args->filename = argv[optind];

	err = 0;

out:
	return err;
}

int main(int argc, char * const *argv)
{
	int ret = -1;
	struct args args;
	int err;
	
	int app_fd = -1;
	void *app_map = NULL;
	size_t app_size;

	char *patched_name = NULL;
	int patched_fd = -1;

	const struct mach_header *mh;
	const struct encryption_info_command *encryption;
	const struct linkedit_data_command *signature;
	const struct symtab_command *symtab;
	const struct dysymtab_command *dysymtab;

	struct nlist *new_symtab = NULL;
	size_t new_symtab_size;
	char *new_strtab = NULL;
	size_t new_strtab_size;
	uint32_t padding = 0;
	size_t nlist_size;

	uint8_t *data;
	size_t size;
	void *__text_data;
	uint64_t __text_offset;
	uint64_t __text_address;
	void *decrypted_buffer = NULL;

	err = parse_options(&args, argc, argv);
	if (err) { 
		error_out(
			"Usage: %s [options...] <filename>\n"
			"Options:\n"
			"  -a, --arch <arch>   Select a specific slice\n"
			"  -n, --no-objc       Ignore ObjectiveC symbols\n"
			"  -d, --decrypt       Dump decrypted __text\n"
			"  -s, --symbol <symbol>=<address>  Add a symbol\n"
			"  -v, --verbose       Verbose mode\n",
			argv[0]);
	}

	app_fd = open(args.filename, O_RDONLY);
	if (app_fd < 1) {
		error_out("%s: %s\n", args.filename, strerror(errno));
	}

	err = map_file(app_fd, &app_map, &app_size);
	if (err || !app_map) {
		error_out("Can't map file: %s\n", strerror(errno));
	}

	if (!args.arch) {
		args.arch = macho_current_arch();
	}

	mh = macho_header_for_arch(app_map, args.arch);
	if (!mh) {
		error_out("Can't find %s slice\n", args.arch);
	}

	verbose("-> Patching %s slice\n", args.arch);

	/* Get encryption info */
	if (macho_is_64(mh)) {
		encryption = macho_get_load_command(mh, LC_ENCRYPTION_INFO_64);
	}
	else {
		encryption = macho_get_load_command(mh, LC_ENCRYPTION_INFO);
	}
	if (!encryption || encryption->cryptid == 0) {
		encryption = NULL;
		verbose("-> Object is not encrypted\n");
	}

	/* Get symbol table info */
	symtab = macho_get_load_command(mh, LC_SYMTAB);
	if (!symtab) {
		error_out("Image has no symbole table\n");
	}
	
	/* Get optional commands */
	dysymtab = macho_get_load_command(mh, LC_DYSYMTAB);
	signature = macho_get_load_command(mh, LC_CODE_SIGNATURE);
	
	err = macho_section_info(
		mh, "__TEXT", "__text",
		&__text_address, &__text_offset, NULL);
	if (err < 0) {
		error_out("Can't find __text\n");
	}

	__text_data = (uint8_t*)mh + __text_offset;

	/* Dump encrypted __text from memory */
	if (encryption) {
		decrypted_buffer = malloc(encryption->cryptsize);

		verbose("-> Snooping decrypted __text\n");
		
		err = dump_decrypted(
			decrypted_buffer, args.filename, args.arch,
			encryption->cryptoff, encryption->cryptsize);
		if (err < 0) {
			error_out("Can't dump decrypted memory\n");
		}

		__text_data = (uint8_t*)decrypted_buffer + __text_offset - encryption->cryptoff;
	}

	nlist_size = macho_is_64(mh) ? sizeof(struct nlist_64) : sizeof(struct nlist);

	/* Create extended symtab */
	if (!args.no_objc) {
		/* Find objective-c symbols */
		err = create_symtab_from_classlist(
			mh, __text_data, __text_address,
			&new_symtab, &new_symtab_size,
			&new_strtab, &new_strtab_size);
		if (err) {
			error_out("Can't find ObjectiveC symbols\n");
		}

		verbose("-> Found %lu ObjectiveC symbols\n", new_symtab_size / nlist_size);
	}

	if (args.symbols) {
		struct symbol_option *symbol;

		verbose("-> Adding %d symbols:\n", args.nsymbols);

		symbol = args.symbols;
		for (int i = 0; i < args.nsymbols; i++, symbol++) {
			verbose("%016llx %s\n", symbol->address, symbol->name);

			err = macho_add_symbol(
				mh,
				&new_symtab, &new_symtab_size,
				&new_strtab, &new_strtab_size,
				symbol->name, symbol->address);
			if (err) {
				error_out("Can't add symbols\n");
			}

			free(symbol->name);
		}
	}

	/* Create patched file */
	patched_name = create_patched_name(args.filename);
	patched_fd = open(patched_name, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (patched_fd < 0) {
		error_out("%s: %s\n", patched_name, strerror(errno));
	}

	/* Copy [filebegin:machobegin[ */
	err = write(patched_fd, app_map, (uint64_t)mh - (uint64_t)app_map);
	if (err < 0) {
		error_out("%s\n", strerror(errno));
	}

	data = (uint8_t*)mh;
	if (args.decrypt && encryption) {
		/* Copy [machobegin:encrypted_begin[ */
		size = encryption->cryptoff;
		err = write(patched_fd, data, size);
		if (err < 0) {
			error_out("Write: %s\n", strerror(errno));
		}
		data += size;

		/* Copy [encrypted_begin:encrypted_end[ from memory */
		size = encryption->cryptsize;
		err = write(patched_fd, decrypted_buffer, size);
		if (err < 0) {
			error_out("Write: %s\n", strerror(errno));
		}
		data += size;

		/* Copy [encrypted_end:symtab_end] */
		size = symtab->symoff + symtab->nsyms * nlist_size;
		size -= encryption->cryptoff + encryption->cryptsize;
		err = write(patched_fd, data, size);
		if (err < 0) {
			error_out("Write: %s\n", strerror(errno));
		}
		data += size;
	}
	else {
		/* Copy [archbegin:symtab_end] */
		size = symtab->symoff + symtab->nsyms * nlist_size;
		err = write(patched_fd, data, size);
		if (err < 0) {
			error_out("Write: %s\n", strerror(errno));
		}
		data += size;
	}

	if (new_symtab || args.symbols) {
		verbose("-> Writing symbol table\n");
		
		/* Add objc symtab */
		err = write(patched_fd, new_symtab, new_symtab_size);
		if (err < 0) {
			error_out("Symbol table: %s\n", strerror(errno));
		}
	}

	/* Copy [symtab_end+1:strtab_end] */
	size = symtab->stroff + symtab->strsize;
	size -= symtab->symoff + symtab->nsyms * nlist_size + 1;
	err = write(patched_fd, data, size);
	if (err < 0) {
		error_out("Write: %s\n", strerror(errno));
	}
	data += size;

	if (new_symtab || args.symbols) {
		uint32_t align;

		/* Add objc strtab */
		err = write(patched_fd, new_strtab, new_strtab_size);
		if (err < 0) {
			error_out("String table: %s\n", strerror(errno));
		}
		/* Add padding */
		align = 2 << macho_align(app_map, args.arch);
		if ((new_symtab_size + new_strtab_size) % align) {
			padding = align - (new_symtab_size + new_strtab_size) % align;
		}

		if (padding) {
			err = write(patched_fd, data - padding, padding);
			if (err < 0) {
				error_out( "Write: %s\n", strerror(errno));
			}
		}
	}

	/* Copy [strtab_end+1:fileend] */
	size = app_size - (uint64_t)data + (uint64_t)app_map;
	err = write(patched_fd, data, size);
	if (err < 0) {
		error_out("Write: %s\n", strerror(errno));
	}

	/* Fix-up object */
	if (new_symtab || args.symbols) {
		verbose("-> Fixing-up mach object\n");

		struct fat_header *arch_header = (struct fat_header *)app_map;
		if (arch_header->magic == FAT_CIGAM) {
			const NXArchInfo *info = NXGetArchInfoFromName(args.arch);
			struct fat_arch *arch = (struct fat_arch *)(arch_header+1);
			int i;	

			/* Fix arch object size */
			for (i = 0; i < __builtin_bswap32(arch_header->nfat_arch); i++, arch++) {
				if (info->cputype == __builtin_bswap32(arch->cputype) &&
				    info->cpusubtype == __builtin_bswap32(arch->cpusubtype)) {

					struct fat_arch arch_fixup = *arch;
					uint32_t size = __builtin_bswap32(arch_fixup.size);

					size += new_symtab_size + new_strtab_size;
					arch_fixup.size = __builtin_bswap32(size);

					lseek(patched_fd, (uint64_t)arch - (uint64_t)app_map, SEEK_SET);
					if (err < 0) {
						error_out("Lseek: %s\n", strerror(errno));
					}
					write(patched_fd, &arch_fixup, sizeof(arch_fixup));
					if (err < 0) {
						error_out("Write: %s\n", strerror(errno));
					}

					break;
				}
			}

			/* Fix offset of following arch */
			for (i++, arch++; i < __builtin_bswap32(arch_header->nfat_arch); i++, arch++) {
				struct fat_arch arch_fixup = *arch;
				uint32_t offset = __builtin_bswap32(arch_fixup.offset);

				offset += new_symtab_size + new_strtab_size + padding;
				arch_fixup.offset = __builtin_bswap32(offset);

				lseek(patched_fd, (uint64_t)arch - (uint64_t)app_map, SEEK_SET);
				if (err < 0) {
					error_out("Lseek: %s\n", strerror(errno));
				}
				write(patched_fd, &arch_fixup, sizeof(arch_fixup));
				if (err < 0) {
					error_out("Write: %s\n", strerror(errno));
				}
			}
		}
	
		/* Fixup symtab */
		struct symtab_command symtab_fixup = *symtab;
		symtab_fixup.nsyms += new_symtab_size / nlist_size;
		symtab_fixup.stroff += new_symtab_size;
		symtab_fixup.strsize += new_strtab_size;

		lseek(patched_fd, (uint64_t)symtab - (uint64_t)app_map, SEEK_SET);
		if (err < 0) {
			error_out("Lseek: %s\n", strerror(errno));
		}
		write(patched_fd, &symtab_fixup, sizeof(symtab_fixup));
		if (err < 0) {
			error_out("Write: %s\n", strerror(errno));
		}

		/* Fixup dynamic symtab */
		if (dysymtab) {
			struct dysymtab_command dysymtab_fixup = *dysymtab;
			dysymtab_fixup.indirectsymoff += new_symtab_size;

			lseek(patched_fd, (uint64_t)dysymtab - (uint64_t)app_map, SEEK_SET);
			if (err < 0) {
				error_out("Lseek: %s\n", strerror(errno));
			}
			write(patched_fd, &dysymtab_fixup, sizeof(dysymtab_fixup));
			if (err < 0) {
				error_out("Write: %s\n", strerror(errno));
			}
		}
	}

	/* Disable encryption */
	if (args.decrypt && encryption) {
		verbose("-> Disabling encrytion\n");

		struct encryption_info_command encryption_fixup = *encryption;
		encryption_fixup.cryptid = 0;

		lseek(patched_fd, (uint64_t)encryption - (uint64_t)app_map, SEEK_SET);
		if (err < 0) {
			error_out("Lseek: %s\n", strerror(errno));
		}	
		write(patched_fd, &encryption_fixup, sizeof(encryption_fixup));
		if (err < 0) {
			error_out("Write: %s\n", strerror(errno));
		}
	}

	/* Disable code signature */
	if (signature) {
		struct linkedit_data_command signature_fixup = *signature;
		signature_fixup.dataoff += new_symtab_size + new_strtab_size;
		if (args.decrypt) {
			verbose("-> Disabling code signature\n");
			signature_fixup.cmd = LC_IDENT; /* obsolete */
		}

		lseek(patched_fd, (uint64_t)signature - (uint64_t)app_map, SEEK_SET);
		if (err < 0) {
			error_out("Lseek: %s\n", strerror(errno));
		}
		write(patched_fd, &signature_fixup, sizeof(signature_fixup));
		if (err < 0) {
			error_out("Write: %s\n", strerror(errno));
		}
	}

	printf("Saved unstripped object in %s\n", patched_name);

	ret = 0;

out:
	/* Housekeeping please */

	if (args.symbols) {
		free(args.symbols);
	}
	if (new_symtab) {
		free(new_symtab);
	}
	if (new_strtab) {
		free(new_strtab);
	}
	if (decrypted_buffer) {
		free(decrypted_buffer);
	}
	if (app_map) {
		munmap(app_map, app_size);
	}
	if (app_fd >= 0) {
		close(app_fd);
	}
	if (patched_name) {
		free(patched_name);
	}
	if (patched_fd >= 0) {
		close(patched_fd);
	}

	return ret;
}