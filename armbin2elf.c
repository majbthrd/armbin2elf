/*
    command-line tool to convert one or more ARM/THUMB binaries into an ELF image
    Copyright (C) 2018 Peter Lawrence

    Permission is hereby granted, free of charge, to any person obtaining a 
    copy of this software and associated documentation files (the "Software"), 
    to deal in the Software without restriction, including without limitation 
    the rights to use, copy, modify, merge, publish, distribute, sublicense, 
    and/or sell copies of the Software, and to permit persons to whom the 
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in 
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
    DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>

typedef struct Elf32_Ehdr
{
	uint8_t e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} Elf32_Ehdr;

typedef struct Elf32_Shdr
{
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint32_t sh_addr;
	uint32_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
} Elf32_Shdr;

typedef struct Elf32_Phdr
{
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
} Elf32_Phdr;

typedef struct Elf32_Sym
{
       uint32_t  st_name;
       uint32_t  st_value;
       uint32_t  st_size;
       uint8_t   st_info;
       uint8_t   st_other;
       uint16_t  st_shndx;
} Elf32_Sym;

_Static_assert(52 == sizeof(Elf32_Ehdr), "struct Elf32_Ehdr is not packed");
_Static_assert(40 == sizeof(Elf32_Shdr), "struct Elf32_Shdr is not packed");
_Static_assert(32 == sizeof(Elf32_Phdr), "struct Elf32_Phdr is not packed");
_Static_assert(16 == sizeof(Elf32_Sym),  "struct Elf32_Sym is not packed");

struct memory_blob
{
	uint32_t address, count;
	uint8_t *data;
	struct memory_blob *next;
};

static Elf32_Ehdr eh =
{
	.e_ident = { 0x7F, 'E', 'L', 'F', 1, 1, 1, },
	.e_type = 2,
	.e_machine = 0x28 /* ARM */,
	.e_version = 1,
	.e_phoff = sizeof(Elf32_Ehdr),
	.e_flags = 0x05000200,
	.e_ehsize = sizeof(Elf32_Ehdr),
	.e_phentsize = sizeof(Elf32_Phdr),
	.e_shentsize = sizeof(Elf32_Shdr),
};

static char section_header_string_table[] = "\x00.shstrtab\x00.text\x00.strtab\x00.symtab";
static char string_table[] = "\x00$t\x00$a";

static struct memory_blob *find_blob(uint32_t address, uint32_t count, struct memory_blob **list)
{
	struct memory_blob *current, *previous, *addition;

	current = *list; previous = NULL;
	while (current)
	{
		if (current->address > address)
			break;

		previous = current;
		current = current->next;
	}

	addition = malloc(sizeof(struct memory_blob));
	memset(addition, 0, sizeof(struct memory_blob));

	addition->data = malloc(count);
	addition->address = address;
	addition->count = count;
	addition->next = current;

	if (previous)
		previous->next = addition;
	else
		*list = addition;

	return addition;
}

int main(int argc, char *argv[])
{
	FILE *elffp;
	FILE *binfp;
	int i;
	Elf32_Phdr ph;
	Elf32_Shdr sh;
	Elf32_Sym st;
	struct memory_blob *blob, *pm_list;
	long file_size;
	int blob_count, blob_sum;
	uint32_t elf_offset, entry_addr, blob_addr;
	const int extra_sections = 1 /* shstrtab */ + 1 /* strtab */ + 1 /* symtab */;

	if (argc < 5)
	{
		printf("%s <output.elf> <entry_address> <input1.bin> <input1_addr> [<input2.bin> <input2_addr> ... <inputn.bin> <inputn_addr>]\n", argv[0]);
		return -1;
	}

	/* attempt to open the file that we will write the ELF to */

	entry_addr = strtoul(argv[2], NULL, 0);

	elffp = fopen(argv[1], "wb");
	if (!elffp)
	{
		printf("ERROR: unable to open file <%s> for writing\n", argv[1]);
		return -1;
	}

	/* load each of the binary files into memory */

	pm_list = NULL; blob_count = 0, blob_sum = 0;

	for (i = 3; i < argc; i += 2)
	{
		binfp = fopen(argv[i], "rb");
		if (!binfp)
		{
			printf("ERROR: unable to open file <%s> for reading\n", argv[3]);
			return -1;
		}

		blob_addr = strtoul(argv[i + 1], NULL, 0);

		fseek(binfp, 0, SEEK_END);
		file_size = ftell(binfp);
		fseek(binfp, 0, SEEK_SET);

		blob = find_blob(blob_addr, file_size, &pm_list);

		fread(blob->data, blob->count, 1, binfp);
		fclose(binfp);

		printf("addr 0x%08x size %li file %s\n", blob_addr, file_size, argv[i]);

		blob_count++; blob_sum += blob->count, blob = blob->next;
	}

	/* the ELF writing starts here */

	/* Step 1: write ELF Header */

	eh.e_entry = entry_addr;
	eh.e_phnum = blob_count;
	eh.e_shnum = 1 /* first NULL section */ + blob_count + extra_sections;
	eh.e_shstrndx = blob_count + extra_sections; /* index to Elf32_Shdr for shstrtab */
	eh.e_shoff = eh.e_phoff + blob_count * sizeof(Elf32_Phdr) + blob_sum;
	fwrite(&eh, sizeof(eh), 1, elffp);

	elf_offset = eh.e_phoff + blob_count * sizeof(Elf32_Phdr);

	/* Step 2: write Program Headers (one for each binary blob) */

	for (blob = pm_list; blob; blob = blob->next)
	{
		ph.p_type = 1;
		ph.p_offset = elf_offset;
		ph.p_vaddr = ph.p_paddr = blob->address;
		ph.p_filesz = ph.p_memsz = blob->count;
		ph.p_flags = 0x5;
		ph.p_align = 1;

		fwrite(&ph, sizeof(ph), 1, elffp);

		elf_offset += blob->count;
	}

	/* Step 3: write each of the binary blobs */

	for (blob = pm_list; blob; blob = blob->next)
	{
		fwrite(blob->data, blob->count, 1, elffp);
	}

	elf_offset = eh.e_phoff + blob_count * sizeof(Elf32_Phdr);

	/* Step 4A: write the prefix Section Header */

	memset(&sh, 0, sizeof(sh));
	fwrite(&sh, sizeof(sh), 1, elffp);

	/* Step 4B: write a Section Header for each binary blob */

	for (blob = pm_list; blob; blob = blob->next)
	{
		sh.sh_name = 11; // point to .text in shstrtab
		sh.sh_type = 1; // SHT_PROGBITS
		sh.sh_flags = 6; // SHF_ALLOC | SHF_EXECINSTR
		sh.sh_addr = blob->address;
		sh.sh_offset = elf_offset;
		sh.sh_size = blob->count;
		sh.sh_link = 0;
		sh.sh_info = 0;
		sh.sh_addralign = 1;
		sh.sh_entsize = 0;
		fwrite(&sh, sizeof(sh), 1, elffp);

		elf_offset += blob->count;
	}

	elf_offset += (1 + blob_count + extra_sections) * sizeof(sh);

	/* Step 4C: write a Section Header for each of extra_sections */

	sh.sh_name = 25; // point to .symtab in shstrtab
	sh.sh_type = 2; // SHT_SYMTAB
	sh.sh_flags = 0x0;
	sh.sh_addr = 0;
	sh.sh_offset = elf_offset;
	sh.sh_size = (blob_count + 1) * sizeof(Elf32_Sym);
	sh.sh_link = 2 + blob_count;
	sh.sh_info = 2;
	sh.sh_addralign = 4;
	sh.sh_entsize = sizeof(Elf32_Sym);
	fwrite(&sh, sizeof(sh), 1, elffp);

	elf_offset += sh.sh_size;

	sh.sh_name = 17; // point to .strtab in shstrtab
	sh.sh_type = 3; // SHT_STRTAB
	sh.sh_flags = 0x0;
	sh.sh_addr = 0;
	sh.sh_offset = elf_offset;
	sh.sh_size = sizeof(string_table);
	sh.sh_link = 0;
	sh.sh_info = 0;
	sh.sh_addralign = 1;
	sh.sh_entsize = 0;
	fwrite(&sh, sizeof(sh), 1, elffp);

	elf_offset += sh.sh_size;

	sh.sh_name = 1; // point to .shstrtab in shstrtab
	sh.sh_type = 3; // SHT_STRTAB
	sh.sh_flags = 0x0;
	sh.sh_addr = 0;
	sh.sh_offset = elf_offset;
	sh.sh_size = sizeof(section_header_string_table);
	sh.sh_link = 0;
	sh.sh_info = 0;
	sh.sh_addralign = 1;
	sh.sh_entsize = 0;
	fwrite(&sh, sizeof(sh), 1, elffp);

	elf_offset += sh.sh_size;

	/* Step 5: write Symbol Table */

	memset(&st, 0, sizeof(st));
	fwrite(&st, sizeof(st), 1, elffp);

	for (blob = pm_list, i = 0; blob; blob = blob->next, i++)
	{
		/* mark as THUMB / ARM based on entry_addr bit 0 */
		st.st_name = (entry_addr & 1) ? 1 : 2; /* point to either $t or $a in strtab */
		st.st_value = ( (entry_addr >= blob->address) && (entry_addr < (blob->address + blob->count)) ) ? (entry_addr & ~1) : blob->address;
		st.st_size = 0;
		st.st_info = 0;
		st.st_other = 0;
		st.st_shndx = 1 + i;
		fwrite(&st, sizeof(st), 1, elffp);
	}

	/* Step 6: write String Table */

	fwrite(string_table, sizeof(string_table), 1, elffp);

	/* Step 7: write Section Header String Table */

	fwrite(section_header_string_table, sizeof(section_header_string_table), 1, elffp);

	/* the ELF writing finishes here */

	fclose(elffp);

	return 0;
}

